package wirelatency

import (
	"container/list"
	"github.com/postwait/gopacket"
	"github.com/postwait/gopacket/layers"
	"github.com/postwait/gopacket/tcpassembly"
	"github.com/postwait/gopacket/tcpassembly/tcpreader"
	"log"
	"strconv"
	"sync/atomic"
	"time"
)

type tcpStreamFactory struct {
	interpFactory *TCPProtocolInterpreterFactory
	name          string
	port          layers.TCPPort
	useReaders    bool
	inFlight      bool
	n_clients     int64
	n_sessions    int64
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
	reader                              *tcpreader.ReaderStream
	parent                              *tcpTwoWayStream
}
type noopTcpStream struct {
}

var sessions = make(map[gopacket.Flow]map[gopacket.Flow]*tcpTwoWayStream)

func isLocalDst(e gopacket.Endpoint) bool {
	// If we have no local addresses we're busted and can't deny this is local
	if !haveLocalAddresses {
		return true
	}
	is_mine, _ := localAddresses[e]
	return is_mine
}
func (twa *tcpTwoWayStream) release() bool {
	if twa.inCreated {
		select {
		case <-twa.cleanupIn:
			twa.inCreated = false
			if *debug_capture {
				log.Printf("[DEBUG] %v cleaned up in", twa)
			}
		default:
		}
	}
	if twa.outCreated {
		select {
		case <-twa.cleanupOut:
			twa.outCreated = false
			if *debug_capture {
				log.Printf("[DEBUG] %v cleaned up out", twa)
			}
		default:
		}
	}

	if !twa.inCreated && !twa.outCreated {
		if twa.in != nil {
			twa.in.parent = nil
			twa.in.reader = nil
		}
		twa.in = nil
		if twa.out != nil {
			twa.out.parent = nil
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
			if *debug_capture {
				log.Printf("[DEBUG] discarding %v:%v", net, transport)
			}
			return &noopTcpStream{}
		}
	}
	net_session := net
	transport_session := transport
	if !inbound {
		net_session = net.Reverse()
		transport_session = transport.Reverse()
	}

	if *debug_capture {
		log.Printf("[DEBUG] New(%v, %v)\n", net, transport)
	}
	// Setup the two level session hash
	// session[localnet:remotenet][localport:remoteport] -> &tcpTwoWayStream
	dsess, ok := sessions[net_session]
	if !ok {
		if *debug_capture {
			log.Printf("[DEBUG] establishing sessions for net:%v", net_session)
		}
		dsess = make(map[gopacket.Flow]*tcpTwoWayStream)
		sessions[net_session] = dsess
	}
	parent, pok := dsess[transport_session]
	if !pok {
		if *debug_capture {
			log.Printf("[DEBUG] establishing dsessions for ports:%v", transport_session)
		}
		interp := (*factory.interpFactory).New()
		parent = &tcpTwoWayStream{interp: &interp, factory: factory}
		parent.cleanupIn = make(chan bool, 1)
		parent.cleanupOut = make(chan bool, 1)
		dsess[transport_session] = parent
	}

	// We can't very will have new streams where we have old streams.
	if inbound && parent.in != nil {
		return &noopTcpStream{}
	}
	if !inbound && parent.out != nil {
		return &noopTcpStream{}
	}

	// Handle the inbound initial session startup
	interp := *parent.interp
	if inbound {
		if *debug_capture {
			log.Printf("[DEBUG] new inbound TCP stream %v:%v started, paired: %v", net_session, transport_session, parent.out != nil)
		}
		atomic.AddInt64(&factory.n_clients, 1)
		atomic.AddInt64(&factory.n_sessions, 1)
		s := &tcpStream{
			inbound:   true,
			parent:    parent,
			net:       net,
			transport: transport,
			start:     time.Now(),
		}
		if factory.useReaders {
			r := tcpreader.NewReaderStream()
			s.reader = &r
		}
		parent.inCreated = true
		parent.in = s
		s.end = s.start
		if factory.useReaders {
			go func() {
				if *debug_capture {
					log.Printf("[DEBUG] go ManageIn(%v:%v) started", s.net, s.transport)
				}
				interp.ManageIn(parent)
				if *debug_capture {
					log.Printf("[DEBUG] go ManageIn(%v:%v) ended", s.net, s.transport)
				}
				s.reader = nil
				close(parent.cleanupIn)
			}()
		} else {
			close(parent.cleanupIn)
		}
		return s
	}

	if *debug_capture {
		log.Printf("[DEBUG] new outbound TCP stream %v:%v started, paired: %v", net_session, transport_session, parent.in != nil)
	}
	// The outbound return session startup
	s := &tcpStream{
		inbound:   false,
		parent:    parent,
		net:       net,
		transport: transport,
		start:     time.Now(),
	}
	if factory.useReaders {
		r := tcpreader.NewReaderStream()
		s.reader = &r
	}
	parent.outCreated = true
	parent.out = s
	if factory.useReaders {
		go func() {
			if *debug_capture {
				log.Printf("[DEBUG] go ManageOut(%v:%v) started", s.net, s.transport)
			}
			interp.ManageOut(parent)
			if *debug_capture {
				log.Printf("[DEBUG] go ManageOut(%v:%v) ended", s.net, s.transport)
			}
			s.reader = nil
			close(parent.cleanupOut)
		}()
	} else {
		close(parent.cleanupOut)
	}
	return s
}
func (f *tcpStreamFactory) Error(name string) {
	if metrics != nil {
		metricname := f.name + "`" + f.port.String() + "`error`" + name
		metrics.Increment(metricname)
	}
}
func (s *noopTcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
}
func (s *noopTcpStream) ReassemblyComplete() {
}

func (s *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	if s.parent == nil || s.parent.factory == nil || s.parent.state == sessionStateBad {
		if *debug_capture {
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
			if *debug_capture {
				log.Printf("[DEBUG] %v skip: %v", direction, reassembly.Skip)
			}
			parent.state = sessionStateBad
		} else if parent.state != sessionStateGood {
			if *debug_capture {
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
			if *debug_capture_data {
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
		s.packets += 1
		if reassembly.Skip > 0 {
			s.skipped += int64(reassembly.Skip)
		}
		s.sawStart = s.sawStart || reassembly.Start
		s.sawEnd = s.sawEnd || reassembly.End
	}

	if s.reader != nil {
		s.reader.Reassembled(reassemblies)
	}
}
func (s *tcpStream) ReassemblyComplete() {
	net_session := s.net
	transport_session := s.transport
	if !s.inbound {
		net_session = s.net.Reverse()
		transport_session = s.transport.Reverse()
	}

	if reader := s.reader; reader != nil {
		if *debug_capture {
			log.Printf("[DEBUG] reassembly complete (inbound: %v): %v:%v", s.inbound, s.net, s.transport)
		}
		s.reader.ReassemblyComplete()
	}
	if dsess, ok := sessions[net_session]; ok {
		if parent, ok := dsess[transport_session]; ok {
			factory := parent.factory
			if *debug_capture {
				log.Printf("[DEBUG] reassembly done %v:%v", s.net, s.transport)
				log.Printf("[DEBUG] removing sub session: %v:%v", s.net, s.transport)
			}
			delete(dsess, transport_session)
			atomic.AddInt64(&factory.n_sessions, -1)
			factory.cleanup <- parent
		}
		if len(dsess) == 0 {
			if *debug_capture {
				log.Printf("[DEBUG] removing session: %v", s.net)
			}
			delete(sessions, net_session)
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
	return (*p).name
}
func (p *TCPProtocol) DefaultPort() layers.TCPPort {
	return (*p).defaultPort
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
			func() uint64 { return uint64(factory.n_clients) })
		metrics.SetGaugeFunc(base+"`active_sessions",
			func() int64 { return factory.n_sessions })
	}
	go factory.doCleanup()
	return factory
}
