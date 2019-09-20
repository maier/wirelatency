// Copyright © 2016 Circonus, Inc. <support@circonus.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package wirelatency

import (
	"encoding/binary"
	"flag"
	"log"
	"strings"
	"time"

	"github.com/golang/snappy"
)

var debugCQL = flag.Bool("debug_cql", false, "Debug cassandra cql reassembly")

const (
	retainedPayloadSize int = 512

	cmdERROR        = uint8(0x00)
	cmdSTARTUP      = uint8(0x01)
	cmdREADY        = uint8(0x02)
	cmdAUTHENTICATE = uint8(0x03)
	cmdCREDENTIALS  = uint8(0x04)
	cmdOPTIONS      = uint8(0x05)
	cmdSUPPORTED    = uint8(0x06)
	cmdQUERY        = uint8(0x07)
	cmdRESULT       = uint8(0x08)
	cmdPREPARE      = uint8(0x09)
	cmdEXECUTE      = uint8(0x0A)
	cmdREGISTER     = uint8(0x0B)
	cmdEVENT        = uint8(0x0C)

	flagCOMPRESSION = uint8(0x01)
	// flag_TRACING     = uint8(0x02)
)

type cassandraCQLFrame struct {
	complete               bool
	soFar                  int
	response               bool
	version, flags, opcode uint8
	stream                 int16
	length                 uint32
	lengthBytes            [4]byte
	payload                []byte
	data                   []byte // the uncompressed frame payload
	truncated              bool   // don't use the payload, it's not all there

	//
	timestamp time.Time
}
type cassandraCQLParser struct {
	factory       *cassandraCQLParserFactory
	streams       map[int16][]cassandraCQLFrame
	requestFrame  cassandraCQLFrame
	responseFrame cassandraCQLFrame
}

func cassandraCQLFrameOpcodeName(code uint8) string {
	switch code {
	case cmdERROR:
		return "Error"
	case cmdSTARTUP:
		return "Startup"
	case cmdREADY:
		return "Ready"
	case cmdAUTHENTICATE:
		return "Authenticate"
	case cmdCREDENTIALS:
		return "Credentials"
	case cmdOPTIONS:
		return "Options"
	case cmdSUPPORTED:
		return "Supported"
	case cmdQUERY:
		return "Query"
	case cmdRESULT:
		return "Result"
	case cmdPREPARE:
		return "Prepare"
	case cmdEXECUTE:
		return "Execute"
	case cmdREGISTER:
		return "Register"
	case cmdEVENT:
		return "Event"
	}
	return "unknown"
}
func (f *cassandraCQLFrame) OpcodeName() string {
	return cassandraCQLFrameOpcodeName(f.opcode)
}
func (f *cassandraCQLFrame) init() {
	f.complete = false
	f.response = false
	f.soFar = 0
	f.version = 0
	f.flags = 0
	f.stream = 0
	f.opcode = 0
	f.length = 0
	f.data = nil
	f.truncated = false
	if f.payload == nil || cap(f.payload) != retainedPayloadSize {
		f.payload = make([]byte, retainedPayloadSize)
	}
	f.payload = f.payload[:0]
}

// Takes "more" data in and attempts to complete the frame
// returns complete if the frame is complete. Always returns
// the number of bytes of the passed data used.  used should
// be the entire data size if frame is incomplete
// If things go off the rails unrecoverably, used = -1 is returned
func (f *cassandraCQLFrame) fillFrame(seen time.Time, data []byte) (complete bool, used int) {
	if len(data) < 1 {
		return false, 0
	}
	if f.soFar == 0 {
		f.timestamp = seen
		f.version = data[used]
		f.response = (f.version&0x80 == 0x80)
		f.version &= ^uint8(0x80)
		f.soFar++
		used++
	}
	headersize := 9
	if f.version > 2 {
		for ; used < len(data) && f.soFar < headersize; f.soFar, used = f.soFar+1, used+1 {
			switch f.soFar {
			case 0:
			case 1:
				f.flags = data[used]
			case 2:
				f.stream = int16(data[used]) << 8
			case 3:
				f.stream |= int16(data[used])
			case 4:
				f.opcode = data[used]
			case 5:
				f.lengthBytes[0] = data[used]
			case 6:
				f.lengthBytes[1] = data[used]
			case 7:
				f.lengthBytes[2] = data[used]
			case 8:
				f.lengthBytes[3] = data[used]
				f.length = binary.BigEndian.Uint32(f.lengthBytes[:])
			}
		}
	} else {
		headersize = 8
		for ; used < len(data) && f.soFar < headersize; f.soFar, used = f.soFar+1, used+1 {
			switch f.soFar {
			case 0:
			case 1:
				f.flags = data[used]
			case 2:
				f.stream = int16(int8(data[used]))
			case 3:
				f.opcode = data[used]
			case 4:
				f.lengthBytes[0] = data[used]
			case 5:
				f.lengthBytes[1] = data[used]
			case 6:
				f.lengthBytes[2] = data[used]
			case 7:
				f.lengthBytes[3] = data[used]
				f.length = binary.BigEndian.Uint32(f.lengthBytes[:])
			}
		}
	}
	if f.soFar < headersize {
		return false, used
	}
	remaining := f.length - uint32(f.soFar-headersize)
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
	if *debugCQL {
		log.Printf("[cql] need to read %d of %d, just %d capped to %d\n", remaining, f.length, toAppend, cappedAppend)
	}
	if cappedAppend > 0 {
		f.payload = append(f.payload, data[used:(used+int(cappedAppend))]...)
	}
	used += int(toAppend)
	f.soFar += int(toAppend)
	if remaining == toAppend {
		if 0 != (f.flags & flagCOMPRESSION) {
			if data, err := snappy.Decode(nil, f.payload); err == nil {
				f.data = data
			}
		} else {
			f.data = f.payload
		}
		f.complete = true
		return true, used
	}
	return false, used
}
func (p *cassandraCQLParser) pushOnStream(f *cassandraCQLFrame) {
	if _, ok := p.streams[f.stream]; ok {
		p.streams[f.stream] = append(p.streams[f.stream], *f)
	} else {
		p.streams[f.stream] = make([]cassandraCQLFrame, 0, 5)
		p.streams[f.stream] = append(p.streams[f.stream], *f)
	}
}
func (p *cassandraCQLParser) popFromStream(stream int16) (f *cassandraCQLFrame) {
	f = nil
	if fifo, ok := p.streams[stream]; ok {
		if len(fifo) > 0 {
			f = &fifo[0]
			p.streams[stream] = fifo[1:]
		}
	}
	return f
}

func readLongstring(data []byte) (out string, ok bool) {
	if len(data) < 4 {
		return "", false
	}
	strlen := binary.BigEndian.Uint32(data)
	if len(data) < (4 + int(strlen)) {
		return "", false
	}
	return string(data[4 : strlen+4]), true
}

func (p *cassandraCQLParser) report(req, resp *cassandraCQLFrame) {
	defaultCQL := "unknown cql"
	cql := &defaultCQL
	if req.opcode == cmdQUERY && req.data != nil {
		if qcql, ok := readLongstring(req.data); ok {
			cql = &qcql
		}
	}
	if req.opcode == cmdPREPARE && req.data != nil {
		if qcql, ok := readLongstring(req.data); ok {
			if resp.data != nil && len(resp.data) >= 2 {
				qcql = strings.Replace(qcql, "\n", " ", -1)
				qcql = strings.Replace(qcql, "\r", " ", -1)
				cql = &qcql
				p.factory.parsed[binary.BigEndian.Uint16(resp.data)] = *cql
			}
		}
	}
	if req.opcode == cmdEXECUTE && req.data != nil && len(req.data) >= 2 {
		id := binary.BigEndian.Uint16(req.data)
		if preparedCQL, ok := p.factory.parsed[id]; ok {
			cql = &preparedCQL
		} else {
			cql = &defaultCQL
		}
	}

	duration := resp.timestamp.Sub(req.timestamp)

	name := req.OpcodeName()

	wlTrackInt64("bytes", int64(req.length), name+"`request_bytes")
	wlTrackInt64("bytes", int64(resp.length), name+"`response_bytes")
	wlTrackFloat64("seconds", float64(duration)/1000000000.0, name+"`latency")

	if req.opcode == cmdEXECUTE {
		// track query-specific execute metrics, in addition to aggregate
		execName := name + "`" + *cql
		wlTrackInt64("bytes", int64(req.length), execName+"`request_bytes")
		wlTrackInt64("bytes", int64(resp.length), execName+"`response_bytes")
		wlTrackFloat64("seconds", float64(duration)/1000000000.0, execName+"`latency")
	}
}
func (p *cassandraCQLParser) InBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	// build a request
	for {
		if len(data) == 0 {
			if *debugCQL {
				log.Printf("[cql] incomplete in frame\n")
			}
			return true
		}
		complete, used := p.requestFrame.fillFrame(seen, data)
		if !complete {
			if *debugCQL {
				log.Printf("[cql] incomplete in frame\n")
			}
			return true
		}
		if used < 0 {
			if *debugCQL {
				log.Printf("[cql] bad in frame\n")
			}
			return false
		}
		if complete {
			p.pushOnStream(&p.requestFrame)
			data = data[used:]
			p.requestFrame.init()
		}
	}
}
func (p *cassandraCQLParser) OutBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	for {
		if len(data) == 0 {
			if *debugCQL {
				log.Printf("[cql] incomplete out frame\n")
			}
			return true
		}
		complete, used := p.responseFrame.fillFrame(seen, data)
		if !complete {
			if *debugCQL {
				log.Printf("[cql] incomplete out frame\n")
			}
			return true
		}
		if used < 0 {
			if *debugCQL {
				log.Printf("[cql] bad out frame\n")
			}
			return false
		}
		if complete {
			req := p.popFromStream(p.responseFrame.stream)
			if *debugCQL {
				log.Printf("[cql] %p response %+v\n", req, &p.responseFrame)
			}
			if req != nil {
				p.report(req, &p.responseFrame)
			}
			data = data[used:]
			p.responseFrame.init()
		}
	}
}
func (p *cassandraCQLParser) ManageIn(stream *tcpTwoWayStream) {
}
func (p *cassandraCQLParser) ManageOut(stream *tcpTwoWayStream) {
}

type cassandraCQLParserFactory struct {
	parsed map[uint16]string
}

func (f *cassandraCQLParserFactory) New() TCPProtocolInterpreter {
	p := cassandraCQLParser{}
	p.factory = f
	p.streams = make(map[int16][]cassandraCQLFrame)
	p.requestFrame.init()
	p.responseFrame.init()
	return &p
}
func init() {
	factory := &cassandraCQLParserFactory{}
	factory.parsed = make(map[uint16]string)
	cassProt := &TCPProtocol{name: "cassandra_cql", defaultPort: 9042}
	cassProt.interpFactory = factory
	RegisterTCPProtocol(cassProt)
}
