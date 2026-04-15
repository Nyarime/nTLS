package nrtp

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

// PortalServeHTTP 在TLS连接上serve HTTP Portal
func PortalServeHTTP(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.Body.Close()

		body := portalHTML
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
			"Server: Cisco ASDM\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Strict-Transport-Security: max-age=31536000\r\n"+
			"X-Frame-Options: SAMEORIGIN\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n\r\n%s", len(body), body)
		conn.Write([]byte(resp))

		if req.Header.Get("Connection") == "close" {
			return
		}
	}
}
