package main

import (
	"encoding/binary"
	"net"
)

// TCP flag constants.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// tcpPacketInfo holds parsed fields from a raw IPv4/TCP packet.
type tcpPacketInfo struct {
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	Flags      uint8
	PayloadLen int
}

// hasFlag checks if a TCP flag is set.
func (p *tcpPacketInfo) hasFlag(flag uint8) bool {
	return p.Flags&flag != 0
}

// parseTCPPacket parses raw IPv4 bytes (no ethernet header) into a tcpPacketInfo.
// Returns nil if the packet is not a valid IPv4/TCP packet.
func parseTCPPacket(data []byte) *tcpPacketInfo {
	if len(data) < 40 { // minimum: 20 IP + 20 TCP
		return nil
	}
	if data[0]>>4 != 4 { // IPv4
		return nil
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+20 {
		return nil
	}
	if data[9] != 6 { // TCP protocol
		return nil
	}

	tcp := data[ihl:]
	dataOffset := int(tcp[12]>>4) * 4
	if dataOffset < 20 {
		return nil
	}
	payloadLen := len(tcp) - dataOffset
	if payloadLen < 0 {
		payloadLen = 0
	}

	return &tcpPacketInfo{
		SrcIP:      net.IP(append([]byte{}, data[12:16]...)),
		DstIP:      net.IP(append([]byte{}, data[16:20]...)),
		SrcPort:    binary.BigEndian.Uint16(tcp[0:2]),
		DstPort:    binary.BigEndian.Uint16(tcp[2:4]),
		Seq:        binary.BigEndian.Uint32(tcp[4:8]),
		Ack:        binary.BigEndian.Uint32(tcp[8:12]),
		Flags:      tcp[13],
		PayloadLen: payloadLen,
	}
}

// buildFakeTCPPacket constructs a raw IPv4/TCP packet with PSH+ACK flags
// and the given payload. Used to inject fake TLS ClientHello data.
func buildFakeTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, payload []byte) []byte {
	const ipHdrLen = 20
	const tcpHdrLen = 20
	totalLen := ipHdrLen + tcpHdrLen + len(payload)

	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45 // version=4, IHL=5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[6] = 0x40 // flags: Don't Fragment
	pkt[8] = 64   // TTL
	pkt[9] = 6    // protocol: TCP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	// IP checksum (kernel recomputes for IPPROTO_RAW on Linux, but set for correctness)
	binary.BigEndian.PutUint16(pkt[10:12], checksumRFC1071(pkt[:ipHdrLen]))

	// TCP header
	tcp := pkt[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 0x50            // data offset: 5 words (20 bytes)
	tcp[13] = tcpPSH | tcpACK // flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window size

	// Copy payload
	copy(pkt[ipHdrLen+tcpHdrLen:], payload)

	// TCP checksum (must be computed by us for raw sockets)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(srcIP.To4(), dstIP.To4(), tcp[:tcpHdrLen], payload))

	return pkt
}

// tcpChecksum computes the TCP checksum including the IPv4 pseudo-header.
func tcpChecksum(srcIP, dstIP []byte, tcpHeader, payload []byte) uint16 {
	tcpLen := len(tcpHeader) + len(payload)

	// Pseudo-header (12 bytes) + TCP segment
	buf := make([]byte, 12+tcpLen)
	copy(buf[0:4], srcIP)
	copy(buf[4:8], dstIP)
	buf[8] = 0
	buf[9] = 6 // TCP protocol number
	binary.BigEndian.PutUint16(buf[10:12], uint16(tcpLen))
	copy(buf[12:], tcpHeader)
	copy(buf[12+len(tcpHeader):], payload)

	return checksumRFC1071(buf)
}

// checksumRFC1071 computes an internet checksum per RFC 1071.
func checksumRFC1071(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
