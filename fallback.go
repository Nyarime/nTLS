package nrtp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type Fallback struct {
	Mode        string
	Target      string
	HTTPHandler http.Handler
}

func (f *Fallback) Handle(conn net.Conn) {
	defer conn.Close()
	switch f.Mode {
	case "handler":
		if f.HTTPHandler != nil {
			serveHTTPOnConn(conn, f.HTTPHandler)
		}
	case "proxy":
		backend, err := net.Dial("tcp", f.Target)
		if err != nil { return }
		defer backend.Close()
		done := make(chan struct{}, 2)
		go func() { io.Copy(backend, conn); done <- struct{}{} }()
		go func() { io.Copy(conn, backend); done <- struct{}{} }()
		<-done
	default:
		PortalServeHTTP(conn)
	}
}

func serveHTTPOnConn(conn net.Conn, handler http.Handler) {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil { return }

		// 缓冲响应body以计算Content-Length
		rw := &bufferedResponseWriter{
			header: make(http.Header),
			body:   &bytes.Buffer{},
		}
		handler.ServeHTTP(rw, req)
		req.Body.Close()

		// 写完整HTTP响应
		code := rw.statusCode
		if code == 0 { code = 200 }
		
		resp := fmt.Sprintf("HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
		rw.header.Set("Content-Length", fmt.Sprintf("%d", rw.body.Len()))
		rw.header.Set("Connection", "Keep-Alive")
		rw.header.Set("Date", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
		for k, vs := range rw.header {
			for _, v := range vs {
				resp += fmt.Sprintf("%s: %s\r\n", k, v)
			}
		}
		resp += "\r\n"
		conn.Write([]byte(resp))
		conn.Write(rw.body.Bytes())
		// keep-alive: 继续处理下一个请求
	}
}

type bufferedResponseWriter struct {
	header     http.Header
	body       *bytes.Buffer
	statusCode int
}

func (w *bufferedResponseWriter) Header() http.Header { return w.header }
func (w *bufferedResponseWriter) WriteHeader(code int) { w.statusCode = code }
func (w *bufferedResponseWriter) Write(b []byte) (int, error) { return w.body.Write(b) }
