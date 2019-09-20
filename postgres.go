// Copyright © 2016 Circonus, Inc. <support@circonus.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package wirelatency

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var debugPostgres = flag.Bool("debug_postgres", false, "Debug postgres reassembly")

var pgSQLWspRe *regexp.Regexp
var pgDeallocRe *regexp.Regexp

type queryMap struct {
	queryRe *regexp.Regexp
	Query   string
	Name    string
}
type postgresConfig struct {
	AdhocStatements    []queryMap
	PreparedStatements []queryMap
}

func postgresConfigParser(c *string) interface{} {
	config := postgresConfig{
		PreparedStatements: make([]queryMap, 0),
		AdhocStatements:    make([]queryMap, 0),
	}
	if c == nil {
		var defaultDndpoints = make([]queryMap, 1)
		defaultDndpoints[0] = queryMap{
			Query: ".",
			Name:  "",
		}
		config.PreparedStatements = defaultDndpoints
	} else {
		file, e := ioutil.ReadFile(*c)
		if e != nil {
			panic(e)
		}
		err := json.Unmarshal(file, &config)
		if err != nil {
			panic(err)
		}
	}
	for i := 0; i < len(config.AdhocStatements); i++ {
		config.AdhocStatements[i].queryRe = regexp.MustCompile(config.AdhocStatements[i].Query)
	}
	for i := 0; i < len(config.PreparedStatements); i++ {
		config.PreparedStatements[i].queryRe = regexp.MustCompile(config.PreparedStatements[i].Query)
	}

	return config
}

func init() {
	pgSQLWspRe = regexp.MustCompile(`[\r\n\s]+`)
	pgDeallocRe = regexp.MustCompile(`(?i)^\s*DEALLOCATE\s+(\S+)`)
}

const (
	pgRetainedPayloadSize int = 1024
	// we make these up, the don't have codes
	pgStartupF    = uint8(0)
	pgSSLRequestF = uint8(1)

	// frontend
	pgBindF            = uint8('B')
	pgCloseF           = uint8('C')
	pgCopyDataF        = uint8('d')
	pgCopyDoneF        = uint8('c')
	pgCopyFailF        = uint8('f')
	pgDescribeF        = uint8('D')
	pgExecuteF         = uint8('E')
	pgFlushF           = uint8('H')
	pgFunctionCallF    = uint8('F')
	pgParseF           = uint8('P')
	pgPasswordMessageF = uint8('p')
	pgQueryF           = uint8('Q')
	pgSyncF            = uint8('S')
	pgTerminateF       = uint8('X')

	// backend
	pgAuthenticationRequestB = uint8('R')
	pgBackendKeyDataB        = uint8('K')
	pgBindCompleteB          = uint8('2')
	pgCloseCompleteB         = uint8('3')
	pgCommandCompleteB       = uint8('C')
	pgCopyDataB              = uint8('d')
	pgCopyDoneB              = uint8('c')
	pgCopyFailB              = uint8('f')
	pgCopyInResponseB        = uint8('G')
	pgCopyOutResponseB       = uint8('H')
	pgCopyBothResponseB      = uint8('W')
	pgDataRowB               = uint8('D')
	pgEmptyQueryResponseB    = uint8('I')
	pgErrorResponseB         = uint8('E')
	pgFunctionCallResponseB  = uint8('V')
	pgNoDataB                = uint8('n')
	pgNoticeResponseB        = uint8('N')
	pgNotificationResponseB  = uint8('A')
	pgParameterDescriptionB  = uint8('t')
	pgParameterStatusB       = uint8('S')
	pgParseCompleteB         = uint8('1')
	pgPortalSuspendedB       = uint8('s')
	pgReadyForQueryB         = uint8('Z')
	pgRowDescriptionB        = uint8('T')
)

type postgresFrame struct {
	inbound     bool
	first       bool
	complete    bool
	soFar       int
	command     uint8
	length      uint32
	lengthBytes [4]byte
	payload     []byte
	truncated   bool // don't use the payload, it's not all there

	//
	timestamp     time.Time
	shouldLog     bool
	longname      string
	responseBytes int
	responseRows  int
}
type postgresParser struct {
	factory         *postgresParserFactory
	stream          []postgresFrame
	requestFrame    postgresFrame
	responseFrame   postgresFrame
	preparedQueries map[string]string
	portals         map[string]string
}

func postgresFrameCommandNameB(code uint8) (string, bool) {
	switch code {
	case pgAuthenticationRequestB:
		return "AuthenticationRequest", true
	case pgBackendKeyDataB:
		return "BackendKeyData", true
	case pgBindCompleteB:
		return "BindComplete", true
	case pgCloseCompleteB:
		return "CloseComplete", true
	case pgCommandCompleteB:
		return "CommandComplete", true
	case pgCopyDataB:
		return "CopyData", true
	case pgCopyDoneB:
		return "CopyDone", true
	case pgCopyFailB:
		return "CopyFail", true
	case pgCopyInResponseB:
		return "CopyInResponse", true
	case pgCopyOutResponseB:
		return "CopyOutResponse", true
	case pgCopyBothResponseB:
		return "CopyBothResponse", true
	case pgDataRowB:
		return "DataRow", true
	case pgEmptyQueryResponseB:
		return "EmptyQueryResponse", true
	case pgErrorResponseB:
		return "ErrorResponse", true
	case pgFunctionCallResponseB:
		return "FunctionCallResponse", true
	case pgNoDataB:
		return "NoData", true
	case pgNoticeResponseB:
		return "NoticeResponse", true
	case pgNotificationResponseB:
		return "NotificationResponse", true
	case pgParameterDescriptionB:
		return "ParameterDescription", true
	case pgParameterStatusB:
		return "ParameterStatus", true
	case pgParseCompleteB:
		return "ParseComplete", true
	case pgPortalSuspendedB:
		return "PortalSuspended", true
	case pgReadyForQueryB:
		return "ReadyForQuery", true
	case pgRowDescriptionB:
		return "RowDescription", true
	}
	return fmt.Sprintf("unknown:%d", code), false
}
func postgresFrameCommandNameF(code uint8) (string, bool) {
	switch code {
	case pgStartupF:
		return "Startup", true
	case pgSSLRequestF:
		return "SSLRequest", true
	case pgBindF:
		return "Bind", true
	case pgCloseF:
		return "Close", true
	case pgCopyDataF:
		return "CopyData", true
	case pgCopyDoneF:
		return "CopyDone", true
	case pgCopyFailF:
		return "CopyFail", true
	case pgDescribeF:
		return "Describe", true
	case pgExecuteF:
		return "Execute", true
	case pgFlushF:
		return "Flush", true
	case pgFunctionCallF:
		return "FunctionCall", true
	case pgParseF:
		return "Parse", true
	case pgPasswordMessageF:
		return "PasswordMessage", true
	case pgQueryF:
		return "Query", true
	case pgSyncF:
		return "Sync", true
	case pgTerminateF:
		return "Terminate", true
	}
	return fmt.Sprintf("unknown: %c", code), false
}
func (f *postgresFrame) CommandName() string {
	if f.inbound {
		name, _ := postgresFrameCommandNameF(f.command)
		return name
	}
	name, _ := postgresFrameCommandNameB(f.command)
	return name
}
func (f *postgresFrame) copy() *postgresFrame {
	newFrame := *f
	// someone is going to squat on the payload, it's not ours anymore
	newFrame.payload = nil
	return &newFrame
}
func (f *postgresFrame) validateIn() bool {
	_, valid := postgresFrameCommandNameF(f.command)
	return valid
}
func (f *postgresFrame) validateOut() bool {
	_, valid := postgresFrameCommandNameB(f.command)
	return valid
}
func (f *postgresFrame) init() {
	f.first = false
	f.complete = false
	f.soFar = 0
	f.command = 0
	f.length = 0
	f.truncated = false
	f.responseRows = 0
	f.responseBytes = 0
	f.shouldLog = false
	f.longname = ""
	if f.payload == nil || cap(f.payload) != pgRetainedPayloadSize {
		f.payload = make([]byte, 0, pgRetainedPayloadSize)
	}
	f.payload = f.payload[:0]
}

// Takes "more" data in and attempts to complete the frame
// returns complete if the frame is complete. Always returns
// the number of bytes of the passed data used.  used should
// be the entire data size if frame is incomplete
// If things go off the rails unrecoverably, used = -1 is returned
func (f *postgresFrame) fillFrame(seen time.Time, data []byte) (complete bool, used int) {
	if len(data) < 1 {
		return false, 0
	}
	if f.soFar == 0 {
		f.timestamp = seen
		if f.inbound && data[used] != 0 {
			// We might be thinking about a first frame, but that's not going
			// to happen if the first byte is 0, we must be mid stream.
			f.first = false
		}
		if f.first {
			// The first packet is disgusting... it could be
			// a Startup or SSLRequest on the F side
			// or a single character response with no length on the B side
			if *debugPostgres {
				log.Printf("[DEBUG] expecting startup frame")
			}
			if f.inbound {
				f.command = pgStartupF
			} else {
				f.command = data[used]
				used++
				if f.command == uint8('N') {
					f.complete = true
					return true, used
				}
				if f.command == uint8('S') {
					f.complete = true
					return true, used
				}
			}
		} else {
			// Normal packes are sensible, first byte is command
			f.command = data[used]
			used++
		}
		f.soFar++
	}
	// Next four bytes are the length (inclusive of the four bytes?!)
	for ; used < len(data) && f.soFar < 5; f.soFar, used = f.soFar+1, used+1 {
		switch f.soFar {
		case 1:
			f.lengthBytes[0] = data[used]
		case 2:
			f.lengthBytes[1] = data[used]
		case 3:
			f.lengthBytes[2] = data[used]
		case 4:
			f.lengthBytes[3] = data[used]
			f.length = binary.BigEndian.Uint32(f.lengthBytes[:])
		}
	}
	if f.soFar < 5 {
		return false, used
	}

	// Now we read in the legnth
	remaining := f.length - uint32(f.soFar-1)
	toAppend := remaining // how much we're actually reading
	if uint32(len(data)-used) < remaining {
		// not complete
		toAppend = uint32(len(data) - used)
	}
	cappedAppend := toAppend // how much we're actually writing
	if len(f.payload)+int(toAppend) > cap(f.payload) {
		cappedAppend = uint32(cap(f.payload) - len(f.payload))
		f.truncated = true
	}
	if cappedAppend > 0 {
		f.payload = append(f.payload, data[used:(used+int(cappedAppend))]...)
	}
	used += int(toAppend)
	f.soFar += int(toAppend)
	if remaining == toAppend {
		f.complete = true
		if f.inbound && f.first && f.command == pgStartupF {
			// our startup message could be an SSLRequest
			if len(f.payload) == 4 && binary.BigEndian.Uint32(f.payload) == 80877103 {
				// alter this post-facto to an SSLRequest so we can expect the
				// non-compliant response packet
				f.command = pgSSLRequestF
			}
		}
		if *debugPostgres {
			log.Printf("[DEBUG] frame completed")
		}
		return true, used
	}
	if *debugPostgres {
		log.Printf("[DEBUG] frame pending")
	}
	return false, used
}
func (p *postgresParser) pushStream(f *postgresFrame) {
	p.stream = append(p.stream, *f)
}
func (p *postgresParser) popStream() (f *postgresFrame) {
	f = nil
	if len(p.stream) > 0 {
		f, p.stream = &p.stream[0], p.stream[1:]
	}
	return f
}
func (p *postgresParser) peekStream() (f *postgresFrame) {
	if len(p.stream) > 0 {
		return &p.stream[0]
	}
	return nil
}
func (p *postgresParser) flushStream() {
	p.stream = make([]postgresFrame, 0, 2)
}

func pgReadString(data []byte) (string, int) {
	for i, c := range data {
		if c == 0 {
			return string(data[0:i]), i
		}
	}
	return "", -1
}
func (p *postgresParser) bind(req, resp *postgresFrame) {
	if req.command != pgBindF {
		if *debugPostgres {
			log.Printf("[DEBUG] out-of-order %v->%v", req.CommandName(), resp.CommandName())
		}
	}
	var name string
	portal, plen := pgReadString(req.payload)
	if plen < 0 {
		return
	}
	name, nlen := pgReadString(req.payload[plen+1:])
	if nlen < 0 {
		return
	}
	p.portals[portal] = name
}
func (p *postgresParser) store(req, resp *postgresFrame) {
	if req.command != pgParseF {
		if *debugPostgres {
			log.Printf("[DEBUG] out-of-order %v->%v", req.CommandName(), resp.CommandName())
		}
	}
	var name string
	name, len := pgReadString(req.payload)
	if len >= 0 {
		query, qlen := pgReadString(req.payload[len+1:])
		if qlen >= 0 {
			p.preparedQueries[name] =
				strings.TrimSpace(pgSQLWspRe.ReplaceAllLiteralString(query, " "))
			if *debugPostgres {
				log.Printf("PARSED[%v] %v", name, p.preparedQueries[name])
			}
		}
	}
}
func (p *postgresParser) extract(config postgresConfig, req *postgresFrame) {
	req.shouldLog = true
	switch req.command {
	case pgParseF:
		req.shouldLog = false
	case pgExecuteF:
		if pname, len := pgReadString(req.payload); len >= 0 {
			if portal, ok := p.portals[pname]; ok {
				if query, ok := p.preparedQueries[portal]; ok {
					for _, qm := range config.PreparedStatements {
						if qm.queryRe.MatchString(query) {
							switch qm.Name {
							case "RAW":
								req.longname = "Execute`" + query
							case "SHA256":
								bsum := sha256.Sum256([]byte(query))
								csum := hex.EncodeToString(bsum[:])
								req.longname = "Execute`" + csum
							case "":
								req.longname = "Execute`" + qm.Name
							default:
								// do nothing
							}
							break
						}
					}
				}
			}
		}
	case pgQueryF:
		if pname, len := pgReadString(req.payload); len >= 0 {
			if *debugPostgres {
				log.Printf("QUERY[%v]", pname)
			}
			if m := pgDeallocRe.FindStringSubmatch(pname); m != nil {
				if *debugPostgres {
					log.Printf("UNPARSE[%v]", m[1])
				}
				delete(p.preparedQueries, m[1])
				req.shouldLog = false
			} else {
				for _, qm := range config.AdhocStatements {
					if qm.queryRe.MatchString(pname) {
						switch qm.Name {
						case "RAW":
							req.longname = "Query`" + pname
						case "SHA256":
							bsum := sha256.Sum256([]byte(pname))
							csum := hex.EncodeToString(bsum[:])
							req.longname = "Query`" + csum
						case "":
							req.longname = "Query`" + qm.Name
						default:
							// do nothing
						}
						break
					}
				}
			}
		}
	}
}
func (p *postgresParser) report(config postgresConfig, req, resp *postgresFrame) {
	shouldLog := req.shouldLog
	name := req.CommandName()
	duration := resp.timestamp.Sub(req.timestamp)
	types := make([]string, 1, 5)
	types[0] = ""
	result := ""
	if resp.command == pgCommandCompleteB {
		var len int
		if result, len = pgReadString(resp.payload); len >= 0 {
			if *debugPostgres {
				log.Printf("[COMPLETE] %v", result)
			}
		}
	}
	if rfields := strings.Fields(result); len(rfields) > 1 {
		types = append(types, "`"+rfields[0])
		if nrows, err := strconv.ParseInt(rfields[len(rfields)-1], 10, 32); err == nil {
			req.responseRows = int(nrows)
		}
	}
	if shouldLog {
		for _, typename := range types {
			wlTrackInt64("bytes", int64(req.length), name+typename+"`request_bytes")
			wlTrackInt64("bytes", int64(req.responseBytes), name+typename+"`response_bytes")
			wlTrackInt64("tuples", int64(req.responseRows), name+typename+"`response_rows")
			wlTrackFloat64("seconds", float64(duration)/1000000000.0, name+typename+"`latency")
		}
		if req.longname != "" {
			wlTrackInt64("bytes", int64(req.length), req.longname+"`request_bytes")
			wlTrackInt64("bytes", int64(req.responseBytes), req.longname+"`response_bytes")
			wlTrackInt64("tuples", int64(req.responseRows), req.longname+"`response_rows")
			wlTrackFloat64("seconds", float64(duration)/1000000000.0, req.longname+"`latency")
		}
	}
}
func (p *postgresParser) reset() {
	p.stream = make([]postgresFrame, 1)
	p.requestFrame.init()
	p.requestFrame.inbound = true
	p.responseFrame.init()
}
func (p *postgresParser) InBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	// build a request
	for {
		if len(data) == 0 {
			return true
		}

		complete, used := p.requestFrame.fillFrame(seen, data)
		if !complete {
			return true
		}
		if used < 0 {
			if *debugPostgres {
				log.Printf("<- BAD READ IN: %v", used)
			}
			p.reset()
			return true
		}
		if complete {
			if p.requestFrame.first && p.requestFrame.command <= pgSSLRequestF {
				p.responseFrame.first = (p.requestFrame.command == pgSSLRequestF)
				p.requestFrame.init()
				data = data[used:]
				continue
			}
			if !p.requestFrame.validateIn() {
				if *debugPostgres {
					log.Printf("<- BAD FRAME: %v", p.requestFrame.CommandName())
				}
				p.reset()
				return true
			}
			switch p.requestFrame.command {
			case pgBindF:
				fallthrough
			case pgQueryF:
				fallthrough
			case pgExecuteF:
				fallthrough
			case pgParseF:
				if *debugPostgres {
					log.Printf("<- %v queued", p.requestFrame.CommandName())
				}
				p.extract(stream.factory.config.(postgresConfig), &p.requestFrame)
				p.pushStream(p.requestFrame.copy())
			default:
				if *debugPostgres {
					log.Printf("<- %v discard", p.requestFrame.CommandName())
				}
			}
			data = data[used:]
			p.requestFrame.init()
		}
	}
}
func (p *postgresParser) OutBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	var pgConfig postgresConfig
	if stream == nil || stream.factory == nil || stream.factory.config == nil {
		return false
	}
	pgConfig = stream.factory.config.(postgresConfig)
	for {
		if len(data) == 0 {
			return true
		}
		complete, used := p.responseFrame.fillFrame(seen, data)
		if !complete {
			return true
		}
		if used < 0 {
			if *debugPostgres {
				log.Printf("-> BAD READ OUT: %v", used)
			}
			p.reset()
			return true
		}
		if complete {
			if p.responseFrame.first {
				if p.responseFrame.command != uint8('N') {
					if *debugPostgres {
						log.Printf("[DEBUG] abandoning SSL session")
					}
					return false
				}
				if *debugCapture {
					log.Printf("[DEBUG] SSLRequest denied, normal startup")
				}
				data = data[used:]
				p.responseFrame.init()
				p.requestFrame.first = true
				continue
			}
			if !p.responseFrame.validateOut() {
				if *debugPostgres {
					log.Printf("-> BAD FRAME: %v", p.requestFrame.CommandName())
				}
				p.reset()
				return true
			}
			req := p.peekStream()
			if req != nil {
				req.responseBytes += p.responseFrame.soFar
			}

			if *debugPostgres {
				log.Printf("-> %v", p.responseFrame.CommandName())
			}
			if p.responseFrame.command == pgReadyForQueryB {
				p.flushStream()
				req = nil
			}
			if req != nil {
				switch p.responseFrame.command {
				case pgDataRowB:
					req.responseRows++
				case pgBindCompleteB:
					p.bind(p.popStream(), &p.responseFrame)
				case pgParseCompleteB:
					p.store(p.popStream(), &p.responseFrame)
				case pgCommandCompleteB:
					p.report(pgConfig, p.popStream(), &p.responseFrame)
				}
			}

			data = data[used:]
			p.responseFrame.init()
		}
	}
}
func (p *postgresParser) ManageIn(stream *tcpTwoWayStream) {
	panic("postgres wirelatency parser is not async")
}
func (p *postgresParser) ManageOut(stream *tcpTwoWayStream) {
	panic("postgres wirelatency parser is not async")
}

type postgresParserFactory struct {
	// parsed map[uint16]string
}

func (f *postgresParserFactory) New() TCPProtocolInterpreter {
	p := postgresParser{}
	p.factory = f
	p.preparedQueries = make(map[string]string)
	p.portals = make(map[string]string)
	p.reset()
	p.requestFrame.first = true
	return &p
}
func init() {
	factory := &postgresParserFactory{}
	postgresProt := &TCPProtocol{
		name:        "postgres",
		defaultPort: 5432,
		inFlight:    true,
		Config:      postgresConfigParser,
	}
	postgresProt.interpFactory = factory
	RegisterTCPProtocol(postgresProt)
}
