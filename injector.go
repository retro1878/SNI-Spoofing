package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

// ConnID uniquely identifies a TCP connection by its 4-tuple.
type ConnID struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// FakeConnection tracks the TCP handshake state and fake injection
// progress for a single connection being monitored for DPI bypass.
type FakeConnection struct {
	mu          sync.Mutex
	monitor     bool
	synSeq      int64 // -1 = not yet observed
	synAckSeq   int64 // -1 = not yet observed
	schFakeSent bool  // fake send goroutine has been scheduled
	fakeSent    bool  // fake packet has actually been sent

	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16

	fakeData []byte
	Done     chan string // signals completion back to the handler
}

// NewFakeConnection creates a new connection tracker.
func NewFakeConnection(srcIP, dstIP net.IP, srcPort, dstPort uint16, fakeData []byte) *FakeConnection {
	return &FakeConnection{
		monitor:   true,
		synSeq:    -1,
		synAckSeq: -1,
		srcIP:     srcIP,
		dstIP:     dstIP,
		srcPort:   srcPort,
		dstPort:   dstPort,
		fakeData:  fakeData,
		Done:      make(chan string, 1),
	}
}

// ID returns the connection identifier.
func (fc *FakeConnection) ID() ConnID {
	return ConnID{
		SrcIP:   fc.srcIP.String(),
		SrcPort: fc.srcPort,
		DstIP:   fc.dstIP.String(),
		DstPort: fc.dstPort,
	}
}

// Injector captures TCP packets via AF_PACKET and injects fake TLS
// ClientHello packets with intentionally wrong sequence numbers to
// bypass DPI (Deep Packet Inspection) filtering.
type Injector struct {
	localIP  net.IP
	remoteIP net.IP

	connections sync.Map // ConnID -> *FakeConnection

	captureFd int // AF_PACKET socket for passive packet capture
	sendFd    int // IPPROTO_RAW socket for fake packet injection
}

// htons converts a uint16 from host byte order to network byte order.
func htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

// NewInjector creates a new packet injector. Requires root or CAP_NET_RAW.
func NewInjector(localIP, remoteIP string) (*Injector, error) {
	// AF_PACKET + SOCK_DGRAM gives us raw IP packets (no ethernet header).
	// ETH_P_IP (0x0800) must be in network byte order.
	captureFd, err := syscall.Socket(
		syscall.AF_PACKET, syscall.SOCK_DGRAM,
		int(htons(0x0800)),
	)
	if err != nil {
		return nil, fmt.Errorf("capture socket: %w (are you running as root?)", err)
	}

	// IPPROTO_RAW implies IP_HDRINCL — we provide the full IP header.
	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		syscall.Close(captureFd)
		return nil, fmt.Errorf("send socket: %w (are you running as root?)", err)
	}

	return &Injector{
		localIP:   net.ParseIP(localIP).To4(),
		remoteIP:  net.ParseIP(remoteIP).To4(),
		captureFd: captureFd,
		sendFd:    sendFd,
	}, nil
}

// Register adds a connection to be monitored for DPI bypass injection.
func (inj *Injector) Register(conn *FakeConnection) {
	inj.connections.Store(conn.ID(), conn)
}

// Unregister removes a connection from monitoring.
func (inj *Injector) Unregister(conn *FakeConnection) {
	inj.connections.Delete(conn.ID())
}

// Run starts the packet capture loop. Should be called as a goroutine.
func (inj *Injector) Run() {
	buf := make([]byte, 65535)
	for {
		n, _, err := syscall.Recvfrom(inj.captureFd, buf, 0)
		if err != nil {
			continue
		}
		if n < 40 { // minimum IPv4 + TCP header
			continue
		}
		inj.processPacket(buf[:n])
	}
}

func (inj *Injector) processPacket(data []byte) {
	pkt := parseTCPPacket(data)
	if pkt == nil {
		return
	}

	// Determine direction and map to our connection ID (always keyed by local→remote)
	var connID ConnID
	var isOutbound bool

	if pkt.SrcIP.Equal(inj.localIP) && pkt.DstIP.Equal(inj.remoteIP) {
		// Outbound: local → remote
		connID = ConnID{
			SrcIP: pkt.SrcIP.String(), SrcPort: pkt.SrcPort,
			DstIP: pkt.DstIP.String(), DstPort: pkt.DstPort,
		}
		isOutbound = true
	} else if pkt.SrcIP.Equal(inj.remoteIP) && pkt.DstIP.Equal(inj.localIP) {
		// Inbound: remote → local (flip to local→remote for lookup)
		connID = ConnID{
			SrcIP: pkt.DstIP.String(), SrcPort: pkt.DstPort,
			DstIP: pkt.SrcIP.String(), DstPort: pkt.SrcPort,
		}
		isOutbound = false
	} else {
		return
	}

	val, ok := inj.connections.Load(connID)
	if !ok {
		return
	}
	conn := val.(*FakeConnection)

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if !conn.monitor {
		return
	}

	if isOutbound {
		inj.onOutbound(pkt, conn)
	} else {
		inj.onInbound(pkt, conn)
	}
}

// onOutbound processes outbound TCP packets during the handshake.
func (inj *Injector) onOutbound(pkt *tcpPacketInfo, conn *FakeConnection) {
	// After fake send is scheduled, ignore all outbound (including our own injected packet)
	if conn.schFakeSent {
		return
	}

	// SYN packet: record our initial sequence number
	if pkt.hasFlag(tcpSYN) && !pkt.hasFlag(tcpACK) && !pkt.hasFlag(tcpRST) &&
		!pkt.hasFlag(tcpFIN) && pkt.PayloadLen == 0 {
		if conn.synSeq != -1 && conn.synSeq != int64(pkt.Seq) {
			log.Printf("SYN seq changed: %d -> %d", conn.synSeq, pkt.Seq)
			return
		}
		conn.synSeq = int64(pkt.Seq)
		return
	}

	// ACK packet: handshake completion — schedule fake injection
	if pkt.hasFlag(tcpACK) && !pkt.hasFlag(tcpSYN) && !pkt.hasFlag(tcpRST) &&
		!pkt.hasFlag(tcpFIN) && pkt.PayloadLen == 0 {
		if conn.synSeq == -1 {
			return
		}
		if pkt.Seq != uint32(conn.synSeq+1)&0xffffffff {
			return
		}
		if conn.synAckSeq == -1 {
			return
		}
		if pkt.Ack != uint32(conn.synAckSeq+1)&0xffffffff {
			return
		}
		conn.schFakeSent = true
		go inj.sendFakePacket(conn)
		return
	}
}

// onInbound processes inbound TCP packets during the handshake.
func (inj *Injector) onInbound(pkt *tcpPacketInfo, conn *FakeConnection) {
	if conn.synSeq == -1 {
		return
	}

	// SYN-ACK: record the remote's initial sequence number
	if pkt.hasFlag(tcpSYN) && pkt.hasFlag(tcpACK) && !pkt.hasFlag(tcpRST) &&
		!pkt.hasFlag(tcpFIN) && pkt.PayloadLen == 0 {
		if pkt.Ack != uint32(conn.synSeq+1)&0xffffffff {
			return
		}
		if conn.synAckSeq != -1 && conn.synAckSeq != int64(pkt.Seq) {
			return
		}
		conn.synAckSeq = int64(pkt.Seq)
		return
	}

	// Duplicate ACK after fake packet: server responded to our wrong-seq packet
	if pkt.hasFlag(tcpACK) && !pkt.hasFlag(tcpSYN) && !pkt.hasFlag(tcpRST) &&
		!pkt.hasFlag(tcpFIN) && pkt.PayloadLen == 0 && conn.fakeSent {
		if conn.synAckSeq == -1 {
			return
		}
		if pkt.Seq != uint32(conn.synAckSeq+1)&0xffffffff {
			return
		}
		if pkt.Ack != uint32(conn.synSeq+1)&0xffffffff {
			return
		}
		conn.monitor = false
		select {
		case conn.Done <- "fake_data_ack_recv":
		default:
		}
		return
	}
}

// sendFakePacket constructs and sends the fake TLS ClientHello with a wrong
// TCP sequence number. Called in a separate goroutine after a brief delay.
func (inj *Injector) sendFakePacket(conn *FakeConnection) {
	time.Sleep(1 * time.Millisecond)

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if !conn.monitor {
		return
	}

	// Wrong sequence: syn_seq + 1 - payload_length
	// The server drops this (wrong seq), but DPI sees the fake SNI.
	fakeSeq := (uint32(conn.synSeq) + 1 - uint32(len(conn.fakeData))) & 0xffffffff
	fakeAck := (uint32(conn.synAckSeq) + 1) & 0xffffffff

	pkt := buildFakeTCPPacket(
		conn.srcIP, conn.dstIP,
		conn.srcPort, conn.dstPort,
		fakeSeq, fakeAck,
		conn.fakeData,
	)

	// Send via raw socket
	dstAddr := &syscall.SockaddrInet4{}
	copy(dstAddr.Addr[:], conn.dstIP.To4())
	if err := syscall.Sendto(inj.sendFd, pkt, 0, dstAddr); err != nil {
		log.Println("Failed to send fake packet:", err)
		return
	}

	conn.fakeSent = true
}
