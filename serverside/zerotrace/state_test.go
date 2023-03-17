package zerotrace

import (
	"errors"
	"net"
	"testing"
	"time"
)

var (
	dummyAddr = net.ParseIP("1.2.3.4")
)

func TestIsAnswered(t *testing.T) {
	p := &tracePkt{}

	if p.IsAnswered() {
		t.Fatal("Expected empty trace packet to be un-answered.")
	}

	now := time.Now().UTC()
	p.sent = now
	p.recvd = now
	if !p.IsAnswered() {
		t.Fatal("Expected answered trace packet to be answered.")
	}
}

func TestNewTrState(t *testing.T) {
	s := newTrState(dummyAddr)
	if s.tracePkts == nil {
		t.Fatal("Map in trState struct uninitialized.")
	}
}

func TestCreateIPID(t *testing.T) {
	s := newTrState(dummyAddr)

	i := s.createIPID()
	if i == s.createIPID() {
		t.Fatal("Got duplicate IP ID from generator.")
	}

	// Test overflowing IP ID.
	s.ipIDCtr = ^uint16(0)
	i = s.createIPID()
	if i != uint16(0) {
		t.Fatalf("Expected IP ID to overflow to 0 but got %d.", i)
	}
}

func TestAddTracePkt(t *testing.T) {
	s := newTrState(dummyAddr)

	s.AddTracePkt(&tracePkt{
		ttl:  1,
		ipID: 1,
		sent: time.Now().UTC(),
	})
	expected := 1
	if len(s.tracePkts) != expected {
		t.Fatalf("Expected %d recorded packets but got %d.",
			expected, len(s.tracePkts))
	}
}

func TestAddRespPkt(t *testing.T) {
	s := newTrState(dummyAddr)
	p := &respPkt{
		ipID:      1,
		ttl:       1,
		recvd:     time.Now().UTC(),
		recvdFrom: net.ParseIP("1.2.3.4"),
	}

	// Adding a packet in response to a non-existing trace packet should give
	// us an error.
	if err := s.AddRespPkt(p); !errors.Is(err, errInvalidResp) {
		t.Fatalf("Expected error %v but got %v.", errInvalidResp, err)
	}

	s.AddTracePkt(&tracePkt{
		ttl:  1,
		ipID: 1,
		sent: time.Now().UTC(),
	})
	if err := s.AddRespPkt(p); err != nil {
		t.Fatalf("Expected error nil but got %v.", err)
	}
}

func TestIsFinished(t *testing.T) {
	s := newTrState(dummyAddr)
	now := time.Now().UTC()
	p := &tracePkt{
		ttl:  1,
		ipID: 1,
		sent: now,
	}

	s.AddTracePkt(p)
	if s.IsFinished() {
		t.Fatal("Expected traceroute to be unfinished.")
	}

	p.sent = now.Add(-reqTimeout)
	if !s.IsFinished() {
		t.Fatal("Expected traceroute to be finished.")
	}

	p.recvd = now
	if !s.IsFinished() {
		t.Fatal("Expected traceroute to be finished.")
	}
}

func TestSummary(t *testing.T) {
	s := newTrState(dummyAddr)
	if len(s.Summary()) == 0 {
		t.Fatal("Expected string summary of traceroute.")
	}

	now := time.Now().UTC()
	s.AddTracePkt(&tracePkt{
		ipID:  1,
		ttl:   1,
		sent:  now,
		recvd: now,
	})
	if len(s.Summary()) == 0 {
		t.Fatal("Expected string summary of traceroute.")
	}
}

func TestCalcStat(t *testing.T) {
	s := newTrState(dummyAddr)
	now := time.Now().UTC()

	expectedRTT := time.Second
	expectedTTL := uint8(1)
	s.AddTracePkt(&tracePkt{
		ttl:   expectedTTL,
		ipID:  1,
		sent:  now.Add(-expectedRTT),
		recvd: now,
	})
	result := s.CalcStat()
	rtt := result.RTT
	ttlVal := result.ClosestPktTTL
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}
	if ttlVal != expectedTTL {
		t.Fatalf("Expected TTL to be %T but got %T.", expectedTTL, ttlVal)
	}

	// Add a trace packet with an identical TTL but a lower RTT and the same TTL.
	expectedRTT = time.Millisecond * 500
	s.AddTracePkt(&tracePkt{
		ttl:   expectedTTL,
		ipID:  2,
		sent:  now.Add(-expectedRTT),
		recvd: now,
	})

	result = s.CalcStat()
	rtt = result.RTT
	ttlVal = result.ClosestPktTTL
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}
	if ttlVal != expectedTTL {
		t.Fatalf("Expected TTL to be %T but got %T.", expectedTTL, ttlVal)
	}

	// Add a trace packet with a higher TTL (i.e., it got closer to the
	// target).
	expectedTTL+=1
	expectedRTT = time.Second * 2
	s.AddTracePkt(&tracePkt{
		ttl:   expectedTTL,
		ipID:  2,
		sent:  now.Add(-expectedRTT),
		recvd: now,
	})
	result = s.CalcStat()
	rtt = result.RTT
	ttlVal = result.ClosestPktTTL
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}
	if ttlVal != expectedTTL {
		t.Fatalf("Expected TTL to be %T but got %T.", expectedTTL, ttlVal)
	}

	// Add an unanswered packet and make sure that it doesn't affect the RTT.
	expectedTTL += 1
	s.AddTracePkt(&tracePkt{
		ttl:  expectedTTL,
		ipID: 3,
		sent: now.Add(-time.Second * 10),
	})
	result = s.CalcStat()
	rtt = result.RTT
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}

	// Add a packet whose TTL is lower than the existing ones but it got
	// answered by the destination itself, so it should be used to calculate
	// the RTT.
	expectedRTT = time.Second * 3
	expectedTTL = 1
	s.AddTracePkt(&tracePkt{
		ttl:       expectedTTL,
		ipID:      4,
		sent:      now.Add(-expectedRTT),
		recvd:     now,
		recvdFrom: dummyAddr,
	})
	result = s.CalcStat()
	rtt = result.RTT
	ttlVal = result.ClosestPktTTL
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}
	if ttlVal != expectedTTL {
		t.Fatalf("Expected TTL to be %T but got %T.", expectedTTL, ttlVal)
	}
}
