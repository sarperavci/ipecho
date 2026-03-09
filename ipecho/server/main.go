package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// Minimal TCP server that echoes client IP as 4 raw bytes.
// Supports two modes on the same port:
//   - Raw TCP: sends 4 bytes immediately (for SOCKS5/CONNECT tunnels)
//   - HTTP: reads GET request, responds with HTTP + 4-byte body (for forward proxies)
//
// Auto-detects protocol by peeking at first byte with short timeout.

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

	fmt.Printf("IP echo server listening on :%s (TCP + HTTP auto-detect)\n", port)

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

	addr := conn.RemoteAddr().(*net.TCPAddr)
	ip := addr.IP.To4()

	if ip == nil {
		log.Printf("IPv6 client: %s (skipped)\n", addr.IP)
		return
	}

	// Peek first byte with short timeout to detect HTTP
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	peek := make([]byte, 1)
	n, _ := conn.Read(peek)
	conn.SetReadDeadline(time.Time{})

	if n == 1 && peek[0] >= 'A' && peek[0] <= 'Z' {
		// HTTP request detected - drain remaining headers
		buf := make([]byte, 2048)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		conn.Read(buf)
		conn.SetReadDeadline(time.Time{})

		// Minimal HTTP response with 4-byte IP body
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"))
		conn.Write(ip)
		log.Printf("HTTP %s -> %d.%d.%d.%d\n", addr, ip[0], ip[1], ip[2], ip[3])
	} else {
		// Raw TCP - send 4 bytes immediately
		conn.Write(ip)
		log.Printf("TCP  %s -> %d.%d.%d.%d\n", addr, ip[0], ip[1], ip[2], ip[3])
	}
}
