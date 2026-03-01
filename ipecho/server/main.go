package main

import (
	"fmt"
	"log"
	"net"
	"os"
)

// Minimal TCP server that echoes client IP as 4 raw bytes
// Total response: 4 bytes

func main() {
	port := "9999"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Printf("IP echo server listening on :%s\n", port)
	fmt.Println("Response: 4 bytes (raw IPv4)")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}

		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	// Get client IP
	addr := conn.RemoteAddr().(*net.TCPAddr)
	ip := addr.IP.To4()

	if ip == nil {
		// IPv6 - send first 4 bytes or skip
		log.Printf("IPv6 client: %s (skipped)\n", addr.IP)
		return
	}

	// Send 4 raw bytes
	conn.Write(ip)

	log.Printf("%s -> %d.%d.%d.%d\n", addr, ip[0], ip[1], ip[2], ip[3])
}
