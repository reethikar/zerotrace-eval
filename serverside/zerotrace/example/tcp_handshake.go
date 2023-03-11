package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	filter = "tcp[tcpflags] == tcp-ack or tcp[tcpflags] == tcp-syn|tcp-ack and port 443"
)

var (
	errHandshakeIncomplete = errors.New("TCP handshake incomplete")
	errNoConnState         = errors.New("no connection state for given packet")
	errNilTuple            = errors.New("was given uninitialized tuple")
	errNoFourTuple         = errors.New("failed to extract TCP four-tuple")
	errNonHandshakeAck     = errors.New("ignoring ACK that's not part of handshake")
	errNoSynAck            = errors.New("got ACK for non-existing SYN/ACK")
	errNoTcp               = errors.New("not a TCP connection")
)

type fourTuple struct {
	srcPort, dstPort uint16
	srcAddr, dstAddr string
}

// handshake contains the SYN/ACK and ACK segment of a TCP handshake.
type handshake struct {
	synAck  gopacket.Packet
	ack     gopacket.Packet
	lastPkt time.Time
}

// stateMachine keeps track of TCP handshakes.
type stateMachine struct {
	sync.RWMutex
	m map[fourTuple]*handshake
}

func newFourTuple(srcAddr net.IP, srcPort uint16, dstAddr net.IP, dstPort uint16) *fourTuple {
	if srcPort == dstPort {
		if bytes.Compare(srcAddr, dstAddr) < 0 {
			srcPort, dstPort = dstPort, srcPort
			srcAddr, dstAddr = dstAddr, srcAddr
		}
	} else if srcPort < dstPort {
		srcPort, dstPort = dstPort, srcPort
		srcAddr, dstAddr = dstAddr, srcAddr
	}

	return &fourTuple{
		srcAddr: srcAddr.String(),
		srcPort: srcPort,
		dstAddr: dstAddr.String(),
		dstPort: dstPort,
	}
}

func (f *fourTuple) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d",
		f.srcAddr, f.srcPort, f.dstAddr, f.dstPort)
}

// rtt returns the round trip time between the SYN/ACK and the ACK segment.
func (s *handshake) rtt() (time.Duration, error) {
	if !s.complete() {
		return time.Duration(0), errHandshakeIncomplete
	}

	synAckTs := s.synAck.Metadata().Timestamp
	ackTs := s.ack.Metadata().Timestamp

	return ackTs.Sub(synAckTs), nil
}

// complete returns true if we have both the SYN/ACK and the ACK segment.
func (s *handshake) complete() bool {
	return s.synAck != nil && s.ack != nil
}

// heartbeat updates the timestamp that keeps track of when we last observed a
// packet for this TCP connection.  This matters for pruning expired
// connections.
func (s *handshake) heartbeat(p gopacket.Packet) {
	s.lastPkt = p.Metadata().Timestamp
}

func (s *stateMachine) prune() int {
	s.Lock()
	defer s.Unlock()

	now := time.Now()
	deleted := 0
	for t, connState := range s.m {
		if now.Sub(connState.lastPkt) > (30 * time.Second) {
			delete(s.m, t)
			deleted += 1
		}
	}
	return deleted
}

func (s *stateMachine) stateForPkt(p gopacket.Packet) (*handshake, error) {
	tuple, err := pktToTuple(p)
	if err != nil {
		return nil, errNoFourTuple
	}

	// Look up connection state or create it if it does not exist.
	connState, exists := s.m[*tuple]
	if !exists {
		l.Printf("Creating new connection state for %s.", tuple)
		connState = &handshake{
			lastPkt: p.Metadata().Timestamp,
		}
		s.m[*tuple] = connState
	} else if exists && connState.complete() {
		return nil, errNonHandshakeAck
	}

	return connState, nil
}

func (s *stateMachine) add(p gopacket.Packet) error {
	// Prune expired TCP connections before potentially adding new ones.
	if pruned := s.prune(); pruned > 0 {
		l.Printf("Pruned %d connections from state machine.", pruned)
	}
	s.Lock()
	defer s.Unlock()

	connState, err := s.stateForPkt(p)
	if err != nil {
		return err
	}
	connState.heartbeat(p) // TODO: correct?

	if isSynAckSegment(p) {
		l.Println("Adding SYN/ACK segment to connection state.")
		connState.synAck = p
	} else if isAckSegment(p) {
		// Is this ACK in response to the SYN/ACK or is it acknowledging payload?
		if connState.synAck == nil {
			return errNoSynAck
		}
		if !pktsShareHandshake(connState.synAck, p) {
			return errNonHandshakeAck
		}
		l.Println("Adding ACK segment to connection state.")
		connState.ack = p
	} else {
		l.Println("INVARIANT: Ignoring TCP segment that's neither SYN/ACK nor ACK.")
	}
	return nil
}

func (s *stateMachine) rttByTuple(t *fourTuple) (time.Duration, error) {
	s.RLock()
	defer s.RUnlock()

	if t == nil {
		return 0, errNilTuple
	}

	connState, exists := s.m[*t]
	if !exists {
		return 0, errNoConnState
	}
	return connState.rtt()
}

func (s *stateMachine) addAndRtt(p gopacket.Packet) (time.Duration, error) {
	if err := s.add(p); err != nil {
		return 0, err
	}

	tuple, err := pktToTuple(p)
	if err != nil {
		return 0, err
	}
	return s.rttByTuple(tuple)
}

// TODO:
// * make code thread-safe
// * prune data store occasionally

// pktToTuple extracts the four-tuple from the given packet: source IP address,
// source port, destination IP address, destination port.
func pktToTuple(p gopacket.Packet) (*fourTuple, error) {
	var srcAddr, dstAddr net.IP

	// Are we dealing with IPv4 or IPv6?
	if p.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		// IPv4
		v4 := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		srcAddr = v4.SrcIP
		dstAddr = v4.DstIP
		// TODO
		//protocol = uint8(v4.Protocol)
	} else if p.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		// IPv6
		v6 := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		srcAddr = v6.SrcIP
		dstAddr = v6.DstIP
		// TODO
		//protocol = uint8(v6.NextHeader)
	} else {
		return nil, errors.New("not an IPv4 or IPv6 packet")
	}

	tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return newFourTuple(
		srcAddr, uint16(tcp.SrcPort),
		dstAddr, uint16(tcp.DstPort),
	), nil
}

// isSynAckSegment returns true if the given packet is a TCP segment that has
// only its SYN and ACK flags set.
func isSynAckSegment(p gopacket.Packet) bool {
	var tcp *layers.TCP
	if p.TransportLayer().LayerType() == layers.LayerTypeTCP {
		tcp = p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	} else {
		return false
	}
	// Only the SYN/ACK flag must be set.
	if tcp.FIN || tcp.RST || tcp.PSH || tcp.URG || tcp.ECE || tcp.CWR || tcp.NS {
		return false
	}
	return tcp.SYN && tcp.ACK
}

// isAckSegment returns true if the given packet is a TCP segment that has only
// its ACK flag set.
func isAckSegment(p gopacket.Packet) bool {
	var tcp *layers.TCP
	if p.TransportLayer().LayerType() == layers.LayerTypeTCP {
		tcp = p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	} else {
		return false
	}
	// Only the ACK flag must be set.
	if tcp.FIN || tcp.SYN || tcp.RST || tcp.PSH || tcp.URG || tcp.ECE || tcp.CWR || tcp.NS {
		return false
	}
	return tcp.ACK
}

// pktsShareHandshake returns true if the given ack packet acknowledges the
// given synAck packet, i.e., they are part of the same TCP three-way
// handshake.
func pktsShareHandshake(synAck, ack gopacket.Packet) bool {
	var synAckTcp, ackTcp *layers.TCP

	if synAck.TransportLayer().LayerType() == layers.LayerTypeTCP {
		synAckTcp = synAck.Layer(layers.LayerTypeTCP).(*layers.TCP)
	} else {
		return false
	}
	if ack.TransportLayer().LayerType() == layers.LayerTypeTCP {
		ackTcp = ack.Layer(layers.LayerTypeTCP).(*layers.TCP)
	} else {
		return false
	}

	// The ACK segment must acknowledge receipt of the SYN/ACK segment.
	return synAckTcp.Seq == (ackTcp.Ack - 1)
}

func capture(s *stateMachine, iface string) {
	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		l.Fatal(err)
	} else if err := handle.SetBPFFilter(filter); err != nil { // optional
		l.Fatal(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			rtt, err := s.addAndRtt(packet)
			if err == nil {
				l.Printf("Handshake RTT: %s\n", rtt)
			}
		}
	}
}

func parseHostPort(host, port string) (net.IP, uint16, error) {
	addr := net.ParseIP(host)
	if addr == nil {
		return nil, 0, fmt.Errorf("%q not a valid IP address", host)
	}

	base := 10
	bitSize := 16
	intPort, err := strconv.ParseUint(port, base, bitSize)
	if err != nil {
		return nil, 0, err
	}
	return addr, uint16(intPort), nil
}

func connToFourTuple(c net.Conn) (*fourTuple, error) {
	lAddr, rAddr := c.LocalAddr(), c.RemoteAddr()

	if lAddr.Network() != "tcp" || rAddr.Network() != "tcp" {
		return nil, errNoTcp
	}

	lHost, lPort, err := net.SplitHostPort(lAddr.String())
	if err != nil {
		return nil, err
	}
	lIPAddr, lIntPort, err := parseHostPort(lHost, lPort)
	if err != nil {
		return nil, err
	}

	rHost, rPort, err := net.SplitHostPort(rAddr.String())
	if err != nil {
		return nil, err
	}
	rIPAddr, rIntPort, err := parseHostPort(rHost, rPort)
	if err != nil {
		return nil, err
	}

	return newFourTuple(lIPAddr, lIntPort, rIPAddr, rIntPort), nil
}
