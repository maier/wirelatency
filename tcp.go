// Copyright © 2016 Circonus, Inc. <support@circonus.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package wirelatency

import (
	"bufio"
	"container/list"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type tcpStreamFactory struct {
	interpFactory *TCPProtocolInterpreterFactory
	name          string
	port          layers.TCPPort
	useReaders    bool
	inFlight      bool
	numClients    int64
	numSessions   int64
	config        interface{}
	cleanup       chan *tcpTwoWayStream
	cleanupList   *list.List
}

const (
	sessionStateBlank = iota
	sessionStateGood  = iota
	sessionStateBad   = iota
)

type tcpTwoWayStream struct {
	factory               *tcpStreamFactory
	interp                *TCPProtocolInterpreter
	inCreated, outCreated bool
	in, out               *tcpStream
	state                 int
	cleanupIn, cleanupOut chan bool
}

type tcpStream struct {
	inbound                             bool
	net, transport                      gopacket.Flow
	bytes, packets, outOfOrder, skipped int64
	start, end                          time.Time
	sawStart, sawEnd                    bool
	readerTCPCompletemu                 sync.Mutex
	readerTCPComplete                   bool
	readerTCP                           *tcpreader.ReaderStream
	reader                              *bufio.Reader
	reassembliesChannel                 chan []tcpassembly.Reassembly
	reassembliesChannelClosed           bool
	parent                              *tcpTwoWayStream
}
type noopTCPStream struct {
}

var sessions = make(map[gopacket.Flow]map[gopacket.Flow]*tcpTwoWayStream)

func isLocalDst(e gopacket.Endpoint) bool {
	// If we have no local addresses we're busted and can't deny this is local
	if !haveLocalAddresses {
		return true
	}
	return localAddresses[e]
}
func (twa *tcpTwoWayStream) release() bool {
	if twa.inCreated {
		select {
		case <-twa.cleanupIn:
			twa.inCreated = false
			if *debugCapture {
				log.Printf("[DEBUG] %v cleaned up in", twa)
			}
		default:
		}
	}
	if twa.outCreated {
		select {
		case <-twa.cleanupOut:
			twa.outCreated = false
			if *debugCapture {
				log.Printf("[DEBUG] %v cleaned up out", twa)
			}
		default:
		}
	}

	if !twa.inCreated && !twa.outCreated {
		if *debugCapture {
			log.Printf("[DEBUG] cleanup shitting down %v", twa)
		}
		if twa.in != nil {
			twa.in.parent = nil
			twa.in.shutdownReader()
			twa.in.reader = nil
		}
		twa.in = nil
		if twa.out != nil {
			twa.out.parent = nil
			twa.out.shutdownReader()
			twa.out.reader = nil
		}
		twa.out = nil
		twa.factory = nil
		twa.interp = nil
		return true
	}
	return false
}
func (factory *tcpStreamFactory) doCleanup() {
	timer := time.Tick(5 * time.Second)
	for {
		select {
		case tofree := <-factory.cleanup:
			if !tofree.release() {
				factory.cleanupList.PushBack(tofree)
			}

		case <-timer:
			var next *list.Element
			var tofree *tcpTwoWayStream
			for e := factory.cleanupList.Front(); e != nil; e = next {
				next = e.Next()
				tofree = e.Value.(*tcpTwoWayStream)
				if tofree.release() {
					factory.cleanupList.Remove(e)
				}
			}
		}
	}
}
func (factory *tcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	inbound := transport.Dst().String() == strconv.Itoa(int(factory.port)) && isLocalDst(net.Dst())
	if !inbound {
		if !(transport.Src().String() == strconv.Itoa(int(factory.port)) && isLocalDst(net.Src())) {
			if *debugCapture {
				log.Printf("[DEBUG] discarding %v:%v", net, transport)
			}
			return &noopTCPStream{}
		}
	}
	netSession := net
	transportSession := transport
	if !inbound {
		netSession = net.Reverse()
		transportSession = transport.Reverse()
	}

	if *debugCapture {
		log.Printf("[DEBUG] New(%v, %v) -> %v\n", net, transport, inbound)
	}
	// Setup the two level session hash
	// session[localnet:remotenet][localport:remoteport] -> &tcpTwoWayStream
	dsess, ok := sessions[netSession]
	if !ok {
		if *debugCapture {
			log.Printf("[DEBUG] establishing sessions for net:%v", netSession)
		}
		dsess = make(map[gopacket.Flow]*tcpTwoWayStream)
		sessions[netSession] = dsess
	}
	parent, pok := dsess[transportSession]
	if !pok {
		if *debugCapture {
			log.Printf("[DEBUG] establishing dsessions for ports:%v", transportSession)
		}
		interp := (*factory.interpFactory).New()
		parent = &tcpTwoWayStream{interp: &interp, factory: factory}
		parent.cleanupIn = make(chan bool, 1)
		parent.cleanupOut = make(chan bool, 1)
		atomic.AddInt64(&factory.numClients, 1)
		atomic.AddInt64(&factory.numSessions, 1)
		dsess[transportSession] = parent
	}

	// We can't very will have new streams where we have old streams.
	if inbound && parent.in != nil {
		return &noopTCPStream{}
	}
	if !inbound && parent.out != nil {
		return &noopTCPStream{}
	}

	// Handle the inbound initial session startup
	interp := *parent.interp
	if inbound {
		if *debugCapture {
			log.Printf("[DEBUG] new inbound TCP stream %v:%v started, paired: %v", net, transport, parent.out != nil)
		}
		s := &tcpStream{
			inbound:   true,
			parent:    parent,
			net:       net,
			transport: transport,
			start:     time.Now(),
		}
		parent.inCreated = true
		parent.in = s
		s.end = s.start
		if factory.useReaders {
			s.startReader()
			go func() {
				if *debugCapture {
					log.Printf("[DEBUG] go ManageIn(%v:%v) started", s.net, s.transport)
				}
				interp.ManageIn(parent)
				if *debugCapture {
					log.Printf("[DEBUG] go ManageIn(%v:%v) ended", s.net, s.transport)
				}
				close(parent.cleanupIn)
			}()
		} else {
			close(parent.cleanupIn)
		}
		return s
	}

	if *debugCapture {
		log.Printf("[DEBUG] new outbound TCP stream %v:%v started, paired: %v", net, transport, parent.in != nil)
	}
	// The outbound return session startup
	s := &tcpStream{
		inbound:   false,
		parent:    parent,
		net:       net,
		transport: transport,
		start:     time.Now(),
	}
	parent.outCreated = true
	parent.out = s
	if factory.useReaders {
		s.startReader()
		go func() {
			if *debugCapture {
				log.Printf("[DEBUG] go ManageOut(%v:%v) started", s.net, s.transport)
			}
			interp.ManageOut(parent)
			if *debugCapture {
				log.Printf("[DEBUG] go ManageOut(%v:%v) ended", s.net, s.transport)
			}
			close(parent.cleanupOut)
		}()
	} else {
		close(parent.cleanupOut)
	}
	return s
}
func (factory *tcpStreamFactory) Error(name string) {
	if metrics != nil {
		metricname := factory.name + "`" + factory.port.String() + "`error`" + name
		metrics.Increment(metricname)
	}
}
func (s *noopTCPStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
}
func (s *noopTCPStream) ReassemblyComplete() {
}

func (s *tcpStream) startReader() {
	r := tcpreader.NewReaderStream()
	s.readerTCP = &r
	s.reader = bufio.NewReader(s.readerTCP)
	s.reassembliesChannel = make(chan []tcpassembly.Reassembly, 10)
	go func(s *tcpStream) {
		defer func() {
			if r := recover(); r != nil {
				if *debugCapture {
					log.Printf("[RECOVERY] tcp/startReader %v\n", r)
				}
			}
		}()
		for {
			reassemblies, ok := <-s.reassembliesChannel
			if !ok {
				s.readerTCPCompletemu.Lock()
				defer s.readerTCPCompletemu.Unlock()
				if !s.readerTCPComplete {
					s.readerTCPComplete = true
					s.readerTCP.ReassemblyComplete()
				}
				return
			}
			s.readerTCP.Reassembled(reassemblies)
		}
	}(s)
}
func (s *tcpStream) shutdownReader() {
	if s.reader == nil {
		return
	}
	if !s.reassembliesChannelClosed {
		s.reassembliesChannelClosed = true
		close(s.reassembliesChannel)
	}
	s.readerTCPCompletemu.Lock()
	defer s.readerTCPCompletemu.Unlock()
	if !s.readerTCPComplete {
		s.readerTCPComplete = true
		s.readerTCP.ReassemblyComplete()
	}
}
func (s *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	if s.parent == nil || s.parent.factory == nil || s.parent.state == sessionStateBad {
		if *debugCapture {
			log.Printf("[DEBUG] %v:%v in bad state", s.net, s.transport)
		}
		/* We know the session is borked, we can avoid reassembling */
		return
	}
	parent := s.parent
	in := parent.in
	inFlight := s.parent.factory.inFlight
	direction := "outbound"
	if s.inbound {
		direction = "inbound"
	}

	for _, reassembly := range reassemblies {
		if reassembly.Skip == 0 || (inFlight && reassembly.Skip < 0) {
			if s.parent == nil {
				return
			}
			if s.parent != nil && (in == s || inFlight) {
				if parent.state == sessionStateBlank {
					parent.state = sessionStateGood
				}
			}
		}
		if reassembly.Skip < 0 && parent.state != sessionStateGood {
			if *debugCapture {
				log.Printf("[DEBUG] %v skip: %v", direction, reassembly.Skip)
			}
			// One side will skip before the other.  If the out
			// side skips first we just need to ignore it until
			// the in side skips and flips the state to "good"
			return
		} else if parent.state != sessionStateGood {
			if *debugCapture {
				log.Printf("[DEBUG] %v entering bad state [from %v]", direction, parent.state)
			}
			parent.state = sessionStateBad
		}
		if reassembly.Seen.Before(s.end) {
			s.outOfOrder++
		} else {
			s.end = reassembly.Seen
		}
		s.bytes += int64(len(reassembly.Bytes))
		if parent.interp != nil {
			if *debugCaptureData {
				log.Printf("[DEBUG] %v %v", direction, reassembly.Bytes)
			}
			if in == s {
				if !(*parent.interp).InBytes(parent, reassembly.Seen, reassembly.Bytes) {
					parent.state = sessionStateBad
				}
			} else {
				if !(*parent.interp).OutBytes(parent, reassembly.Seen, reassembly.Bytes) {
					parent.state = sessionStateBad
				}

			}
		}
		s.packets++
		if reassembly.Skip > 0 {
			s.skipped += int64(reassembly.Skip)
		}
		s.sawStart = s.sawStart || reassembly.Start
		s.sawEnd = s.sawEnd || reassembly.End
	}

	if s.readerTCP != nil {
		mycopy := make([]tcpassembly.Reassembly, len(reassemblies))
		copy(mycopy, reassemblies)
		for i := 0; i < len(mycopy); i++ {
			mycopy[i].Bytes = make([]byte, len(reassemblies[i].Bytes))
			copy(mycopy[i].Bytes, reassemblies[i].Bytes)
		}
		s.reassembliesChannel <- mycopy
		//s.readerTcp.Reassembled(reassemblies)
	}
}
func (s *tcpStream) ReassemblyComplete() {
	netSession := s.net
	transportSession := s.transport
	if !s.inbound {
		netSession = s.net.Reverse()
		transportSession = s.transport.Reverse()
	}

	if s.reassembliesChannel != nil {
		if *debugCapture {
			log.Printf("[DEBUG] reassembly done %v:%v", s.net, s.transport)
		}
		if !s.reassembliesChannelClosed {
			s.reassembliesChannelClosed = true
			close(s.reassembliesChannel)
		}
	}
	if dsess, ok := sessions[netSession]; ok {
		if parent, ok := dsess[transportSession]; ok {
			factory := parent.factory
			if *debugCapture {
				log.Printf("[DEBUG] removing sub session: %v:%v", s.net, s.transport)
			}
			delete(dsess, transportSession)
			atomic.AddInt64(&factory.numSessions, -1)
			factory.cleanup <- parent
		}
		if len(dsess) == 0 {
			if *debugCapture {
				log.Printf("[DEBUG] removing session: %v", s.net)
			}
			delete(sessions, netSession)
		}
	}
}

type TCPProtocolInterpreter interface {
	ManageIn(stream *tcpTwoWayStream)
	ManageOut(stream *tcpTwoWayStream)
	InBytes(stream *tcpTwoWayStream, seen time.Time, bytes []byte) bool
	OutBytes(stream *tcpTwoWayStream, seen time.Time, bytes []byte) bool
}
type TCPProtocolInterpreterFactory interface {
	New() TCPProtocolInterpreter
}

type configbuilder func(*string) interface{}
type TCPProtocol struct {
	name          string
	defaultPort   layers.TCPPort
	useReaders    bool
	inFlight      bool
	interpFactory TCPProtocolInterpreterFactory
	Config        configbuilder
}

func (p *TCPProtocol) Name() string {
	return p.name
}
func (p *TCPProtocol) DefaultPort() layers.TCPPort {
	return p.defaultPort
}
func (p *TCPProtocol) Factory(port layers.TCPPort, config *string) tcpassembly.StreamFactory {
	factory := &tcpStreamFactory{
		name:          p.Name(),
		port:          port,
		useReaders:    p.useReaders,
		inFlight:      p.inFlight,
		interpFactory: &p.interpFactory,
		cleanup:       make(chan *tcpTwoWayStream, 10),
		cleanupList:   list.New(),
	}
	if p.Config != nil {
		factory.config = p.Config(config)
	}
	if metrics != nil {
		base := p.Name() + "`" + port.String()
		metrics.SetCounterFunc(base+"`total_sessions",
			func() uint64 { return uint64(factory.numClients) })
		metrics.SetGaugeFunc(base+"`active_sessions",
			func() int64 { return factory.numSessions })
	}
	go factory.doCleanup()
	return factory
}
