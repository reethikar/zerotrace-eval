package main

import (
	"bytes"
	"encoding/binary"
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
	filter = "tcp[tcpflags] == tcp-syn or tcp[tcpflags] == tcp-ack or tcp[tcpflags] == tcp-syn|tcp-ack and port 443"
)

var (
	errHandshakeIncomplete = errors.New("TCP handshake incomplete")
	errNoConnState         = errors.New("no connection state for given packet")
	errNilTuple            = errors.New("was given uninitialized tuple")
	errNoFourTuple         = errors.New("failed to extract TCP four-tuple")
	errNonHandshakeSynAck  = errors.New("ignoring SYN/ACK that's not part of handshake")
	errNonHandshakeAck     = errors.New("ignoring ACK that's not part of handshake")
	errNoSynAck            = errors.New("got ACK for non-existing SYN/ACK")
	errNoSyn               = errors.New("got SYN/ACK for non-existing SYN")
	errNoTcp               = errors.New("not a TCP connection")
	errInvalidMssSize      = errors.New("MSS size in SYN segment not 4 bytes in length")
	errSynHasNoMss         = errors.New("SYN segment has no MSS option")
	errNoSynSegment        = errors.New("cannot extract information from non-existing SYN segment")
	errIPHasNoTCP          = errors.New("IP packet does not carry TCP segment")
)

type fourTuple struct {
	srcPort, dstPort uint16
	srcAddr, dstAddr string
}

// handshake contains the SYN/ACK and ACK segment of a TCP handshake.
type handshake struct {
	syn     gopacket.Packet
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

func (s *handshake) mss() (uint32, error) {
	if s.syn == nil {
		return 0, errNoSynSegment
	}

	tcp := s.syn.Layer(layers.LayerTypeTCP).(*layers.TCP)
	for _, o := range tcp.Options {
		if o.OptionType == layers.TCPOptionKindMSS {
			if o.OptionLength != uint8(4) {
				return 0, errInvalidMssSize
			}
			// Network byte order uses big endian.
			return uint32(binary.BigEndian.Uint16(o.OptionData)), nil
		}
	}
	return 0, errSynHasNoMss
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

// complete returns true if we have a SYN, SYN/ACK, and ACK.
func (s *handshake) complete() bool {
	return s.syn != nil && s.synAck != nil && s.ack != nil
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
		// Consider a TCP connection timed out after 30 seconds.  Note
		// that it's fine to be strict here because we only care about
		// the TCP handshake.  Subsequent data packets don't matter.
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
		l.Printf("Pruned %d connection(s); %d left.", pruned, len(s.m))
	}
	s.Lock()
	defer s.Unlock()

	connState, err := s.stateForPkt(p)
	if err != nil {
		return err
	}
	// This packet is part of an existing connection.  Reset the expiry
	// timer.
	connState.heartbeat(p)

	if isSynSegment(p) {
		l.Println("Adding SYN segment to connection state.")
		connState.syn = p
	} else if isSynAckSegment(p) {
		if connState.syn == nil {
			return errNoSyn
		}
		if !pktsShareHandshake(connState.syn, p) {
			return errNonHandshakeSynAck
		}
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

func (s *stateMachine) mssByTuple(t *fourTuple) (uint32, error) {
	s.RLock()
	defer s.RUnlock()

	if t == nil {
		return 0, errNilTuple
	}

	connState, exists := s.m[*t]
	if !exists {
		return 0, errNoConnState
	}
	return connState.mss()
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

// pktToTuple extracts the four-tuple from the given packet: source IP address,
// source port, destination IP address, destination port.
func pktToTuple(p gopacket.Packet) (*fourTuple, error) {
	var srcAddr, dstAddr net.IP

	// Are we dealing with IPv4 or IPv6?
	if p.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		v4 := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		srcAddr = v4.SrcIP
		dstAddr = v4.DstIP
		if v4.Protocol != layers.IPProtocolTCP {
			return nil, errIPHasNoTCP
		}
	} else if p.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		v6 := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		srcAddr = v6.SrcIP
		dstAddr = v6.DstIP
		if v6.NextHeader != layers.IPProtocolTCP {
			return nil, errIPHasNoTCP
		}
	} else {
		return nil, errors.New("not an IPv4 or IPv6 packet")
	}

	tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return newFourTuple(
		srcAddr, uint16(tcp.SrcPort),
		dstAddr, uint16(tcp.DstPort),
	), nil
}

// isSynSegment returns true if the given packet is a TCP segment that has
// only its SYN flag set.
func isSynSegment(p gopacket.Packet) bool {
	var tcp *layers.TCP
	if p.TransportLayer().LayerType() == layers.LayerTypeTCP {
		tcp = p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	} else {
		return false
	}
	// Only the SYN flag must be set.
	if tcp.FIN || tcp.RST || tcp.PSH || tcp.URG || tcp.ECE || tcp.CWR || tcp.NS || tcp.ACK {
		return false
	}
	return tcp.SYN
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

// pktsShareHandshake returns true if the given TCP handshake segment
// acknowledges the preceding segment, i.e., the two given packets are part of
// the same TCP three-way handshake.  The function accepts either a SYN and
// SYN/ACK pair or a SYN/ACK and ACK pair.
func pktsShareHandshake(p1, p2 gopacket.Packet) bool {
	var t1, t2 *layers.TCP

	if p1.TransportLayer().LayerType() == layers.LayerTypeTCP {
		t1 = p1.Layer(layers.LayerTypeTCP).(*layers.TCP)
	} else {
		return false
	}
	if p2.TransportLayer().LayerType() == layers.LayerTypeTCP {
		t2 = p2.Layer(layers.LayerTypeTCP).(*layers.TCP)
	} else {
		return false
	}

	// The second packet (either a SYN/ACK or an ACK) must acknowledge
	// receipt of the first packet (either a SYN or a SYN/ACK).
	return t1.Seq == (t2.Ack - 1)
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
