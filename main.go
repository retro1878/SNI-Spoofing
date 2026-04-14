package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// Config holds the application configuration loaded from config.json.
type Config struct {
	ListenHost  string `json:"LISTEN_HOST"`
	ListenPort  int    `json:"LISTEN_PORT"`
	ConnectIP   string `json:"CONNECT_IP"`
	ConnectPort int    `json:"CONNECT_PORT"`
	FakeSNI     string `json:"FAKE_SNI"`
}

var cfg Config

func loadConfig() {
	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatal("Failed to read config.json: ", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatal("Failed to parse config.json: ", err)
	}
	if len(cfg.FakeSNI) > 219 {
		log.Fatal("FAKE_SNI is too long (max 219 bytes)")
	}
}

func main() {
	loadConfig()

	localIP := getDefaultInterfaceIPv4(cfg.ConnectIP)
	if localIP == "" {
		log.Fatal("Could not determine local interface IPv4 address")
	}

	log.Printf("Local interface: %s", localIP)
	log.Printf("Target: %s:%d", cfg.ConnectIP, cfg.ConnectPort)
	log.Printf("Fake SNI: %s", cfg.FakeSNI)

	injector, err := NewInjector(localIP, cfg.ConnectIP)
	if err != nil {
		log.Fatal("Failed to create injector: ", err)
	}
	go injector.Run()

	fmt.Println("هشن شومافر تیامح دینکیم هدافتسا دازآ تنرتنیا هب یسرتسد یارب همانرب نیا زا رگا")
	fmt.Println("دراد امش تیامح هب زاین هک مراد رظن رد دازآ تنرتنیا هب ناریا مدرم مامت یسرتسد یارب یدایز یاه همانرب و اه هژورپ")
	fmt.Println()
	fmt.Println("USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424")
	fmt.Println()
	fmt.Println("@patterniha")
	fmt.Println()

	listenAddr := fmt.Sprintf("%s:%d", cfg.ListenHost, cfg.ListenPort)
	log.Printf("Listening on %s", listenAddr)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal("Failed to listen: ", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleConnection(conn, localIP, injector)
	}
}

// handleConnection processes a single incoming client connection.
// It connects to the remote server, injects a fake TLS ClientHello
// with a spoofed SNI to bypass DPI, then relays traffic bidirectionally.
func handleConnection(clientConn net.Conn, localIP string, injector *Injector) {
	defer clientConn.Close()

	// Generate fake TLS ClientHello with random values
	rnd := make([]byte, 32)
	sessID := make([]byte, 32)
	keyShare := make([]byte, 32)
	rand.Read(rnd)
	rand.Read(sessID)
	rand.Read(keyShare)
	fakeData := buildClientHello(rnd, sessID, []byte(cfg.FakeSNI), keyShare)

	// Create outgoing socket with explicit bind to learn the source port
	fd, srcPort, err := createOutgoingSocket(localIP)
	if err != nil {
		log.Println("Socket error:", err)
		return
	}

	// Register the connection for packet monitoring BEFORE connecting,
	// so the injector captures the SYN and tracks the full handshake.
	fakeConn := NewFakeConnection(
		net.ParseIP(localIP).To4(),
		net.ParseIP(cfg.ConnectIP).To4(),
		srcPort,
		uint16(cfg.ConnectPort),
		fakeData,
	)
	injector.Register(fakeConn)

	// Initiate TCP handshake (blocking). The injector goroutine captures
	// the SYN, SYN-ACK, and ACK packets and injects the fake ClientHello.
	if err := connectSocket(fd, cfg.ConnectIP, cfg.ConnectPort); err != nil {
		injector.Unregister(fakeConn)
		syscall.Close(fd)
		log.Println("Connect error:", err)
		return
	}

	// Wait for the injector to confirm the fake packet was acknowledged.
	select {
	case msg := <-fakeConn.Done:
		if msg != "fake_data_ack_recv" {
			injector.Unregister(fakeConn)
			syscall.Close(fd)
			log.Println("Injection failed:", msg)
			return
		}
	case <-time.After(2 * time.Second):
		fakeConn.mu.Lock()
		fakeConn.monitor = false
		fakeConn.mu.Unlock()
		injector.Unregister(fakeConn)
		syscall.Close(fd)
		log.Println("Injection timeout")
		return
	}

	injector.Unregister(fakeConn)

	// Convert the raw fd to a standard net.Conn for relay
	serverConn, err := fdToConn(fd)
	if err != nil {
		syscall.Close(fd)
		log.Println("fd conversion error:", err)
		return
	}
	defer serverConn.Close()

	relay(clientConn, serverConn)
}

// createOutgoingSocket creates a TCP socket, binds it to the local IP
// (with an ephemeral port), and returns the fd and assigned port.
func createOutgoingSocket(localIP string) (int, uint16, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("socket: %w", err)
	}

	// Keepalive settings matching the Python implementation
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 11)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 2)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)

	// Connect timeout (10 seconds)
	tv := syscall.Timeval{Sec: 10}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)

	ip := net.ParseIP(localIP).To4()
	bindAddr := &syscall.SockaddrInet4{Port: 0}
	copy(bindAddr.Addr[:], ip)
	if err := syscall.Bind(fd, bindAddr); err != nil {
		syscall.Close(fd)
		return 0, 0, fmt.Errorf("bind: %w", err)
	}

	sa, err := syscall.Getsockname(fd)
	if err != nil {
		syscall.Close(fd)
		return 0, 0, fmt.Errorf("getsockname: %w", err)
	}
	port := uint16(sa.(*syscall.SockaddrInet4).Port)

	return fd, port, nil
}

// connectSocket initiates a TCP connection on an existing socket fd.
func connectSocket(fd int, remoteIP string, remotePort int) error {
	ip := net.ParseIP(remoteIP).To4()
	addr := &syscall.SockaddrInet4{Port: remotePort}
	copy(addr.Addr[:], ip)
	return syscall.Connect(fd, addr)
}

// fdToConn converts a raw file descriptor into a net.Conn.
// The fd is duplicated internally; the caller should not close it afterward.
func fdToConn(fd int) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), "tcp")
	defer f.Close() // closes original fd; net.FileConn uses a dup'd copy
	return net.FileConn(f)
}

// relay copies data bidirectionally between two connections until one side closes.
func relay(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		a.Close()
		b.Close()
	}

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(b, a)
		once.Do(closeBoth)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(a, b)
		once.Do(closeBoth)
		done <- struct{}{}
	}()
	<-done
}
