package nrtp

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// XHTTPConfig XHTTP传输配置
type XHTTPConfig struct {
	Path    string            // e.g. /api/v1/stream
	Headers map[string]string // 自定义请求头
	SNI     string
}

// xhttpConn 把HTTP流包装成net.Conn
type xhttpConn struct {
	r      io.ReadCloser
	w      io.Writer
	wFlush func()
	local  net.Addr
	remote net.Addr
	mu     sync.Mutex
}

func (c *xhttpConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *xhttpConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.w.Write(p)
	if c.wFlush != nil { c.wFlush() }
	return n, err
}
func (c *xhttpConn) Close() error                       { return c.r.Close() }
func (c *xhttpConn) LocalAddr() net.Addr                { return c.local }
func (c *xhttpConn) RemoteAddr() net.Addr               { return c.remote }
func (c *xhttpConn) SetDeadline(t time.Time) error      { return nil }
func (c *xhttpConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttpConn) SetWriteDeadline(t time.Time) error { return nil }

// DialXHTTP 客户端通过HTTP POST流连接
func DialXHTTP(addr string, cfg *Config) (net.Conn, error) {
	xCfg := cfg.XHTTP
	if xCfg == nil {
		xCfg = &XHTTPConfig{Path: "/stream"}
	}
	sni := xCfg.SNI
	if sni == "" { sni = cfg.SNI }
	if sni == "" {
		host, _, _ := net.SplitHostPort(addr)
		sni = host
	}
	path := xCfg.Path
	if path == "" { path = "/stream" }

	// 建立TLS连接
	var rawConn net.Conn
	var err error
	if cfg.UseUTLS {
		rawConn, err = DialUTLS(addr, sni, cfg.UTLSFingerprint)
	} else {
		rawConn, err = tls.Dial("tcp", addr, &tls.Config{
			ServerName: sni, InsecureSkipVerify: true,
		})
	}
	if err != nil {
		return nil, err
	}

	// HTTP请求（POST + chunked streaming）
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n", path, sni, ua)
	for k, v := range xCfg.Headers {
		req += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	req += "\r\n"
	rawConn.Write([]byte(req))

	// 读HTTP响应头
	buf := make([]byte, 4096)
	n, err := rawConn.Read(buf)
	if err != nil || n < 12 {
		rawConn.Close()
		return nil, fmt.Errorf("xhttp response error")
	}
	// 只需要确认200
	// 剩余数据是body流

	conn := &xhttpConn{
		r:      io.NopCloser(rawConn),
		w:      rawConn,
		local:  rawConn.LocalAddr(),
		remote: rawConn.RemoteAddr(),
	}

	// PSK认证
	psk := deriveKey(cfg.Password)
	if err := clientAuth(conn, psk); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// XHTTPListener 服务端
type XHTTPListener struct {
	connCh chan net.Conn
	ln     net.Listener
	psk    []byte
	path   string
}

func ListenXHTTP(addr string, cfg *Config) (*XHTTPListener, error) {
	xCfg := cfg.XHTTP
	if xCfg == nil {
		xCfg = &XHTTPConfig{Path: "/stream"}
	}
	path := xCfg.Path
	if path == "" { path = "/stream" }

	tlsCfg, _ := makeTLSConfig(cfg)
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, err
	}

	xl := &XHTTPListener{
		connCh: make(chan net.Conn, 64),
		ln:     ln,
		psk:    deriveKey(cfg.Password),
		path:   path,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		// Hijack连接
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "not supported", 500)
			return
		}

		// 发送200响应
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		conn, buf, _ := hj.Hijack()
		xConn := &xhttpConn{
			r:      io.NopCloser(buf),
			w:      conn,
			local:  conn.LocalAddr(),
			remote: conn.RemoteAddr(),
		}

		// PSK验证
		if err := serverAuth(xConn, xl.psk); err != nil {
			conn.Close()
			return
		}
		xl.connCh <- xConn
	})

	// 回落
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>OK</body></html>"))
	})

	go http.Serve(ln, mux)
	log.Printf("[NRTP] XHTTP 监听 %s (path: %s)", addr, path)

	return xl, nil
}

func (l *XHTTPListener) Accept() (net.Conn, error) {
	conn, ok := <-l.connCh
	if !ok { return nil, fmt.Errorf("closed") }
	return conn, nil
}
func (l *XHTTPListener) Addr() net.Addr { return l.ln.Addr() }
func (l *XHTTPListener) Close() error   { close(l.connCh); return l.ln.Close() }
