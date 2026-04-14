package main

import "net"

// getDefaultInterfaceIPv4 determines the local IPv4 address used to reach targetAddr.
func getDefaultInterfaceIPv4(targetAddr string) string {
	conn, err := net.Dial("udp4", targetAddr+":53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
