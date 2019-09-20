// Copyright © 2016 Circonus, Inc. <support@circonus.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package wirelatency

import (
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var debugHTTP = flag.Bool("debug_wl_http", false, "Debug wirelatency HTTP decoding")

type httpEndpointMap struct {
	pathRe *regexp.Regexp
	Path   string
	Name   string
}
type httpConfig struct {
	Routes []httpEndpointMap
}

type httpReqInfo struct {
	name   string
	method string
	start  time.Time
	size   int
}
type httpRespInfo struct {
	statusName  string
	size        int
	taFirstByte time.Time
	end         time.Time
}
type httpParser struct {
	l        sync.Mutex
	reqinfo  []*httpReqInfo
	respinfo []*httpRespInfo
}

func (p *httpParser) InBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	return true
}
func (p *httpParser) OutBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	return true
}
func (p *httpParser) process() {
	p.l.Lock()
	defer p.l.Unlock()
	for len(p.reqinfo) > 0 && len(p.respinfo) > 0 {
		var req *httpReqInfo
		var resp *httpRespInfo
		req, p.reqinfo = p.reqinfo[0], p.reqinfo[1:]
		resp, p.respinfo = p.respinfo[0], p.respinfo[1:]
		name := req.method + "`" + req.name + "`" + resp.statusName
		ttFirstbyte := math.Max(float64(resp.taFirstByte.Sub(req.start))/1000000000.0, 0.0000001)
		ttDuration := math.Max(float64(resp.end.Sub(req.start))/1000000000.0, 0.0000001)
		wlTrackFloat64("seconds", ttFirstbyte, name+"`firstbyte_latency")
		wlTrackFloat64("seconds", ttDuration, name+"`latency")
		wlTrackInt64("bytes", int64(req.size), name+"`request_bytes")
		wlTrackInt64("bytes", int64(resp.size), name+"`response_bytes")
	}
}
func (p *httpParser) ManageIn(stream *tcpTwoWayStream) {
	defer func() {
		if r := recover(); r != nil {
			if *debugHTTP {
				log.Printf("[RECOVERY] (http/ManageIn): %v\n", r)
			}
		}
	}()
	var config interface{}
	factory := stream.factory
	if factory != nil {
		config = factory.config
	}
	rIn := stream.in.reader
	for {
		var req *http.Request
		_, err := rIn.ReadByte()
		if err == nil {
			err = rIn.UnreadByte()
		}
		if err != nil {
			if *debugHTTP {
				log.Println("[DEBUG] Error parsing HTTP requests:", err)
			}
			return
		}

		startTime := time.Now()

		newReq, err := http.ReadRequest(rIn)
		if err != nil {
			if err != io.EOF && *debugHTTP {
				log.Println("[DEBUG] Error parsing HTTP requests:", err)
			}
			return
		}

		if *debugHTTP {
			log.Println("[DEBUG] new request read.")
		}
		req = newReq
		nbytes, derr := tcpreader.DiscardBytesToFirstError(req.Body)
		if derr != nil && derr != io.EOF {
			if *debugHTTP {
				log.Printf("[DEBUG] error reading request body: %v\n", derr)
			}
			return
		}
		if *debugHTTP {
			log.Println("[DEBUG] Body contains", nbytes, "bytes")
		}
		path := "unknown"
		if req.URL != nil {
			path = req.URL.Path
		}
		p.l.Lock()
		p.reqinfo = append(p.reqinfo, &httpReqInfo{
			name:   URLMatch(config, path),
			method: req.Method,
			start:  startTime,
			size:   nbytes,
		})
		p.l.Unlock()
		p.process()
	}
}

func (p *httpParser) ManageOut(stream *tcpTwoWayStream) {
	defer func() {
		if r := recover(); r != nil {
			if *debugHTTP {
				log.Printf("[RECOVERY] (http/ManageOut): %v\n", r)
			}
		}
	}()
	rOut := stream.out.reader
	for {
		var req *http.Request
		_, err := rOut.ReadByte()
		if err == nil {
			err = rOut.UnreadByte()
		}
		if err != nil {
			if *debugHTTP {
				log.Println("[DEBUG] Error parsing HTTP requests:", err)
			}
			return
		}
		taFirstByte := time.Now()

		resp, err := http.ReadResponse(rOut, req)
		if err != nil {
			if err != io.EOF && *debugHTTP {
				log.Println("[DEBUG] Error parsing HTTP responses:", err)
				log.Printf("[%+v]\n", stream.out)
			}
			return
		}

		if *debugHTTP {
			log.Println("[DEBUG] new response read.")
		}
		nbytes, derr := tcpreader.DiscardBytesToFirstError(resp.Body)
		if derr != nil && derr != io.EOF {
			if *debugHTTP {
				log.Printf("[DEBUG] error reading http response body: %v\n", derr)
			}
			return
		}
		taLastByte := time.Now()
		resp.Body.Close()
		if *debugHTTP {
			log.Println("[DEBUG] Body contains", nbytes, "bytes")
		}
		statusName := "xxx"
		switch {
		case resp.StatusCode >= 0 && resp.StatusCode < 100:
			statusName = "0xx"
		case resp.StatusCode >= 100 && resp.StatusCode < 200:
			statusName = "1xx"
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			statusName = "2xx"
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			statusName = "3xx"
		case resp.StatusCode >= 400 && resp.StatusCode < 500:
			statusName = "4xx"
		case resp.StatusCode >= 500 && resp.StatusCode < 600:
			statusName = "5xx"
		}
		p.l.Lock()
		p.respinfo = append(p.respinfo, &httpRespInfo{
			statusName:  statusName,
			size:        nbytes,
			taFirstByte: taFirstByte,
			end:         taLastByte,
		})
		p.l.Unlock()

		p.process()
	}
}

func URLMatch(iconfig interface{}, url string) string {
	config := iconfig.(httpConfig)
	for _, route := range config.Routes {
		if route.pathRe.MatchString(url) {
			return route.Name
		}
	}
	return "unmatched_route"
}

type httpParserFactory struct{}

func (f httpParserFactory) New() TCPProtocolInterpreter {
	p := httpParser{}
	return &p
}
func httpConfigParser(c *string) interface{} {
	config := httpConfig{Routes: make([]httpEndpointMap, 0)}
	if c == nil {
		var defaultEndpoints = make([]httpEndpointMap, 1)
		defaultEndpoints[0] = httpEndpointMap{
			Path: "^/",
			Name: "default",
		}
		config.Routes = defaultEndpoints
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
	for i := 0; i < len(config.Routes); i++ {
		config.Routes[i].pathRe = regexp.MustCompile(config.Routes[i].Path)
	}

	return config
}
func init() {
	factory := &httpParserFactory{}
	httpProt := &TCPProtocol{
		name:        "http",
		useReaders:  true,
		defaultPort: 80,
		Config:      httpConfigParser,
	}
	httpProt.interpFactory = factory
	RegisterTCPProtocol(httpProt)
}
