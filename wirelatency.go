// Copyright © 2016 Circonus, Inc. <support@circonus.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

// +build go1.13

package wirelatency

import (
	"errors"
	"flag"
	"log"
	"net"
	"runtime"
	"strconv"
	"time"

	cgm "github.com/circonus-labs/circonus-gometrics/v3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

var metrics *cgm.CirconusMetrics
var debugMeasurements = flag.Bool("debug_measurements", false, "Debug measurement recording")
var haveLocalAddresses = false
var localAddresses = make(map[gopacket.Endpoint]bool)

func AddLocalIP(ip net.IP) {
	if ip.To4() != nil {
		haveLocalAddresses = true
		localAddresses[gopacket.NewEndpoint(layers.EndpointIPv4, ip.To4())] = true
	}
	if ip.To16() != nil {
		haveLocalAddresses = true
		localAddresses[gopacket.NewEndpoint(layers.EndpointIPv6, ip.To16())] = true
	}
}

func defaultTags(units string) cgm.Tags {
	tags := cgm.Tags{}
	if units != "" {
		tags = append(tags, cgm.Tag{
			Category: "units",
			Value:    units,
		})
	}
	return tags
}

func wlTrackInt64(units string, value int64, name string) {
	tags := defaultTags(units)
	wlTrackInt64Tagged(name, value, tags)
}
func wlTrackInt64Tagged(name string, value int64, tags cgm.Tags) {
	if *debugMeasurements {
		log.Printf("[METRIC] %s -> %d %v", name, value, tags)
	}
	if metrics != nil {
		metrics.SetHistogramValueWithTags(name, tags, float64(value))
	}
}

func wlTrackFloat64(units string, value float64, name string) {
	tags := defaultTags(units)
	wlTrackFloat64Tagged(name, value, tags)
}
func wlTrackFloat64Tagged(name string, value float64, tags cgm.Tags) {
	if *debugMeasurements {
		log.Printf("[METRIC] %s -> %e %v", name, value, tags)
	}
	if metrics != nil {
		metrics.SetHistogramValueWithTags(name, tags, value)
	}
}

func SetMetrics(m *cgm.CirconusMetrics) {
	metrics = m
}

type WLTCPProtocol interface {
	Name() string
	DefaultPort() layers.TCPPort
	Factory(port layers.TCPPort, config *string) tcpassembly.StreamFactory
}

type twoWayAssembly struct {
	proto     *WLTCPProtocol
	assembler *tcpassembly.Assembler
	Config    *string
}

func (twa *twoWayAssembly) Proto() *WLTCPProtocol {
	return twa.proto
}

var portAssemblerMap = make(map[layers.TCPPort]*twoWayAssembly)
var protocols = make(map[string]*WLTCPProtocol)

func RegisterTCPProtocol(protocol WLTCPProtocol) {
	protocols[protocol.Name()] = &protocol
}

func RegisterTCPPort(port layers.TCPPort, protocolName string, config *string) error {
	wp, ok := protocols[protocolName]
	if !ok {
		return errors.New("bad protocol")
	}
	if port == 0 {
		port = (*wp).DefaultPort()
	}
	if _, exists := portAssemblerMap[port]; exists {
		return errors.New("port already mapped")
	}

	streamFactory := (*wp).Factory(port, config)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	portAssemblerMap[port] = &twoWayAssembly{
		proto:     wp,
		assembler: assembler,
		Config:    config,
	}
	return nil
}

var flushAfter = flag.String("flush_after", "5s",
	"Connections with gaps will have buffered packets flushed after this timeout")
var closeAfter = flag.String("close_after", "2m",
	"Connections with gaps will closed and have buffered packets flushed after this timeout")
var iface = flag.String("iface", "auto", "Select the system interface to sniff")
var debugCaptureData = flag.Bool("debug_capture_data", false, "Debug packet capture data")
var debugCapture = flag.Bool("debug_capture", false, "Debug packet assembly")

func Protocols() map[string]*WLTCPProtocol {
	return protocols
}
func PortMap() map[layers.TCPPort]*twoWayAssembly {
	return portAssemblerMap
}
func selectInterface() string {
	choice := *iface
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, ifaceTry := range ifaces {
		addrs, err := ifaceTry.Addrs()
		if err != nil {
			log.Printf("Error on interface: %v", ifaceTry.Name)
			continue
		}
		for _, ifi := range addrs {
			tryIface := &ifaceTry.Name
			if ip, _, _ := net.ParseCIDR(ifi.String()); ip != nil {
				if ip.IsGlobalUnicast() {
					if ip.To16() != nil {
						haveLocalAddresses = true
						localAddresses[gopacket.NewEndpoint(layers.EndpointIPv6, ip.To16())] = true
					}
					if ip.To4() != nil {
						haveLocalAddresses = true
						localAddresses[gopacket.NewEndpoint(layers.EndpointIPv4, ip.To4())] = true
						if *iface == "auto" {
							choice = *tryIface
							iface = &choice
						}
					}
				}
			}
		}
	}
	return *iface
}

var handles []*pcap.Handle = make([]*pcap.Handle, 0)

func Close() {
	for _, handle := range handles {
		handle.Close()
	}
	handles = make([]*pcap.Handle, 0)
}
func Capture() {
	flushDuration, err := time.ParseDuration(*flushAfter)
	if err != nil {
		log.Fatal("invalid flush duration: ", *flushAfter)
	}
	closeDuration, err := time.ParseDuration(*closeAfter)
	if err != nil {
		log.Fatal("invalid close duration: ", *closeAfter)
	}

	// Construct our BPF filter
	filter := "tcp and ("
	subsequentOr := ""
	for port := range portAssemblerMap {
		filter = filter + subsequentOr + "port " + strconv.Itoa(int(port))
		subsequentOr = " or "
	}
	filter += ")"

	ifname := selectInterface()
	promisc := false
	if runtime.GOOS == "solaris" {
		promisc = true
	}
	if *debugCapture {
		pstr := " "
		if promisc {
			pstr = " [promiscuous] "
		}
		log.Printf("[DEBUG] Activating BPF%sfilter on %v: '%v'", pstr, ifname, filter)
	}
	handle, err := pcap.OpenLive(ifname, 65536, promisc, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}
	handles = append(handles, handle)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	flushTicker := time.Tick(flushDuration / 2)
	closeTicker := time.Tick(closeDuration / 2)

	wakeupAndGC := make(chan bool, 1)
	go func() {
		for {
			if ok := <-wakeupAndGC; !ok {
				break
			}
			runtime.GC()
		}
	}()

	for {
		select {
		case <-flushTicker:
			if *debugCapture {
				stats, _ := handle.Stats()
				log.Printf("[DEBUG] flushing all streams that haven't seen packets, pcap stats: %+v", stats)
			}
			for _, twa := range portAssemblerMap {
				twa.assembler.FlushWithOptions(tcpassembly.FlushOptions{CloseAll: false, T: time.Now().Add(0 - flushDuration)})
			}

		case <-closeTicker:
			if *debugCapture {
				stats, _ := handle.Stats()
				log.Printf("[DEBUG] flushing all streams that haven't seen packets, pcap stats: %+v", stats)
			}
			for _, twa := range portAssemblerMap {
				twa.assembler.FlushOlderThan(time.Now().Add(0 - closeDuration))
			}
			wakeupAndGC <- true

		case packet := <-packets:
			if packet == nil {
				log.Printf("No packets?")
				continue
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			if twa, ok := portAssemblerMap[tcp.SrcPort]; ok {
				twa.assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			}
			if twa, ok := portAssemblerMap[tcp.DstPort]; ok {
				twa.assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			}
		}
	}
}
