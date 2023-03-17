package zerotrace

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

var (
	l = log.New(os.Stderr, "0trace: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
)

// Config holds configuration options for the ZeroTrace object.
type Config struct {
	// NumProbes determines the number of probes we're sending for a given TTL.
	NumProbes int
	// TTLStart determines the TTL at which we start sending trace packets.
	TTLStart int
	// TTLEnd determines the TTL at which we stop sending trace packets.
	TTLEnd int
	// SnapLen determines the number of bytes per frame that we want libpcap to
	// capture.  500 bytes is enough for ICMP TTL exceeded packets.
	SnapLen int32
	// PktBufTimeout determines the time we're willing to wait for packets to
	// accumulate in our receive buffer.
	PktBufTimeout time.Duration
	// Interface determines the network interface that we're going to use to
	// listen for incoming network packets.
	Interface string
}

// NewDefaultConfig returns a configuration object containing the following
// defaults.  *Note* that you probably need to change the networking interface.
//
//   NumProbes:     3
//   TTLStart:      5
//   TTLEnd:        32
//   SnapLen:       500
//   PktBufTimeout: time.Millisecond * 10
//   Interface:     "eth0"
func NewDefaultConfig() *Config {
	return &Config{
		NumProbes:     3,
		TTLStart:      5,
		TTLEnd:        32,
		SnapLen:       500,
		PktBufTimeout: time.Millisecond * 10,
		Interface:     "enp1s0f1",
	}
}

// ZeroTrace implements the 0trace traceroute technique:
// https://seclists.org/fulldisclosure/2007/Jan/145
type ZeroTrace struct {
	sync.RWMutex
	cfg *Config
}

// NewZeroTrace instantiates and returns a new ZeroTrace object that's going to
// use the given configuration for its measurement.
func NewZeroTrace(c *Config) *ZeroTrace {
	return &ZeroTrace{cfg: c}
}

// sendTracePkts sends trace packets to our target.  Once a packet was sent,
// it's written to the given channel.  The given function is used to create an
// IP ID that is set in the trace packet's IP header.
func (z *ZeroTrace) sendTracePkts(c chan *tracePkt, createIPID func() uint16, conn net.Conn) {
	remoteIP, err := extractRemoteIP(conn)
	if err != nil {
		l.Printf("Error extracting remote IP address from connection: %v", err)
		return
	}

	for ttl := z.cfg.TTLStart; ttl <= z.cfg.TTLEnd; ttl++ {
		tempConn := conn.(*tls.Conn)
		tcpConn := tempConn.NetConn()
		ipConn := ipv4.NewConn(tcpConn)

		// Set our net.Conn's TTL for future outgoing packets.
		if err := ipConn.SetTTL(ttl); err != nil {
			l.Printf("Error setting TTL: %v", err)
			return
		}

		for n := 0; n < z.cfg.NumProbes; n++ {
			ipID := createIPID()
			pkt, err := createPkt(conn, ipID)
			if err != nil {
				l.Printf("Error creating packet: %v", err)
				return
			}

			if err := sendRawPkt(
				ipID,
				uint8(ttl),
				remoteIP,
				pkt,
			); err != nil {
				l.Printf("Error sending raw packet: %v", err)
			}

			c <- &tracePkt{
				ttl:  uint8(ttl),
				ipID: ipID,
				sent: time.Now().UTC(),
			}
		}
		l.Printf("Sent %d trace packets with TTL %d.", z.cfg.NumProbes, ttl)
	}
	l.Println("Done sending trace packets.")
}

// CalcStat coordinates our 0trace traceroute and returns the details
// and RTT to the target or, if the target won't respond to us, 
// the details and RTT of the hop that's closest.
// The given net.Conn represents an already-established TCP connection to the
// target.  Note that the TCP connection may be corrupted as part of the 0trace
// measurement.
func (z *ZeroTrace) CalcStat(conn net.Conn) (ZeroTraceResult, error) {
	remoteIP, err := extractRemoteIP(conn)
	if err != nil {
		return ZeroTraceResult{}, err
	}

	state := newTrState(remoteIP)
	ticker := time.NewTicker(time.Second)
	quit := make(chan bool)
	defer close(quit)

	// Set up our pcap handle.
	promiscuous := true
	pcapHdl, err := pcap.OpenLive(
		z.cfg.Interface,
		z.cfg.SnapLen,
		promiscuous,
		z.cfg.PktBufTimeout,
	)
	if err != nil {
		return ZeroTraceResult{}, err
	}
	if err = pcapHdl.SetBPFFilter("icmp"); err != nil {
		return ZeroTraceResult{}, err
	}
	defer pcapHdl.Close()

	// Spawn goroutine that listens for incoming ICMP response packets.
	respChan := make(chan *respPkt)
	go z.recvRespPkts(pcapHdl, respChan, quit)

	// Spawn goroutine that sends trace packets.
	traceChan := make(chan *tracePkt)
	go z.sendTracePkts(traceChan, state.createIPID, conn)

loop:
	for {
		select {
		// We just sent a trace packet.
		case tracePkt := <-traceChan:
			state.AddTracePkt(tracePkt)

		// We just received a packet in response to a trace packet.
		case respPkt := <-respChan:
			if err := state.AddRespPkt(respPkt); err != nil {
				l.Printf("Error adding response packet: %v", err)
			}

		// Check if we're done with the traceroute.
		case <-ticker.C:
			state.Summary()
			if state.IsFinished() {
				break loop
			}
		}
	}

	return state.CalcStat(), nil
}

// recvRespPkts uses the given pcap handle to read incoming packets and filters
// for ICMP TTL exceeded packets that are then sent to the given channel.  The
// function returns when the given quit channel is closed.
func (z *ZeroTrace) recvRespPkts(pcapHdl *pcap.Handle, c chan *respPkt, quit chan bool) {
	packetStream := gopacket.NewPacketSource(pcapHdl, pcapHdl.LinkType())

	for {
		select {
		case <-quit:
			l.Println("Done reading packets.")
			return
		case pkt := <-packetStream.Packets():
			if pkt == nil {
				continue
			}
			ipLayer := pkt.Layer(layers.LayerTypeIPv4)
			icmpLayer := pkt.Layer(layers.LayerTypeICMPv4)

			if ipLayer == nil || icmpLayer == nil {
				continue
			}

			// If it is an ICMP packet, check if it is the ICMP TTL
			// exceeded one we are looking for
			respPkt, err := z.extractRcvdPkt(pkt)
			if err != nil {
				l.Printf("Failed to extract response packet: %v", err)
				continue
			}
			c <- respPkt
		}
	}
}

// extractRcvdPkt extracts what we need (IP ID, timestamp, address) from the
// given network packet.
func (z *ZeroTrace) extractRcvdPkt(packet gopacket.Packet) (*respPkt, error) {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	icmpPkt, _ := icmpLayer.(*layers.ICMPv4)

	ipID, err := extractIPID(icmpPkt.LayerPayload())
	if err != nil {
		return nil, err
	}

	// We're not interested in the response packet's TTL because by
	// definition, it's always going to be 1.
	return &respPkt{
		ipID:      ipID,
		recvd:     packet.Metadata().Timestamp,
		recvdFrom: ipv4Layer.SrcIP,
	}, nil
}
