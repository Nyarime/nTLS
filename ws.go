package ntls

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSConfig WebSocket伪装配置
type WSConfig struct {
	Path    string            // e.g. /api/ws
	Headers map[string]string // 自定义请求头
	SNI     string            // TLS SNI
}

// wsConn 把WebSocket封装成net.Conn
type wsConn struct {
	ws       *websocket.Conn
	readBuf  []byte
	readOff  int
	mu       sync.Mutex
}

func (c *wsConn) Read(p []byte) (int, error) {
	if c.readOff < len(c.readBuf) {
		n := copy(p, c.readBuf[c.readOff:])
		c.readOff += n
		return n, nil
	}

	_, msg, err := c.ws.ReadMessage()
	if err != nil {
		return 0, err
	}
	n := copy(p, msg)
	if n < len(msg) {
		c.readBuf = msg
		c.readOff = n
	} else {
		c.readBuf = nil
		c.readOff = 0
	}
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.ws.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error                       { return c.ws.Close() }
func (c *wsConn) LocalAddr() net.Addr                { return c.ws.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.ws.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error      { return nil }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return nil }

// DialWS 通过WebSocket连接（伪装成正常HTTPS流量）
func DialWS(addr string, cfg *Config) (net.Conn, error) {
	wsCfg := cfg.WS
	if wsCfg == nil {
		wsCfg = &WSConfig{Path: "/ws"}
	}

	sni := wsCfg.SNI
	if sni == "" {
		sni = cfg.SNI
	}
	if sni == "" {
		host, _, _ := net.SplitHostPort(addr)
		sni = host
	}

	path := wsCfg.Path
	if path == "" {
		path = "/ws"
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	header := http.Header{}
	header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	for k, v := range wsCfg.Headers {
		header.Set(k, v)
	}

	url := fmt.Sprintf("ws://%s%s", addr, path)
	ws, _, err := dialer.Dial(url, header)
	if err != nil {
		return nil, fmt.Errorf("ws dial: %w", err)
	}

	conn := &wsConn{ws: ws}

	// PSK认证
	psk := deriveKey(cfg.Password)
	if err := clientAuth(conn, psk); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// ListenWS WebSocket服务端（升级HTTP连接为WebSocket）
type WSListener struct {
	connCh chan net.Conn
	ln     net.Listener
	psk    []byte
	path   string
}

func ListenWS(addr string, cfg *Config) (*WSListener, error) {
	wsCfg := cfg.WS
	if wsCfg == nil {
		wsCfg = &WSConfig{Path: "/ws"}
	}

	path := wsCfg.Path
	if path == "" {
		path = "/ws"
	}


	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	wsl := &WSListener{
		connCh: make(chan net.Conn, 64),
		ln:     ln,
		psk:    deriveKey(cfg.Password),
		path:   path,
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn := &wsConn{ws: ws}

		// PSK验证
		if err := serverAuth(conn, wsl.psk); err != nil {
			conn.Close()
			return
		}

		wsl.connCh <- conn
	})

	// 其他路径返回正常网页（回落）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Welcome</body></html>"))
	})

	go http.Serve(ln, mux)

	return wsl, nil
}

func (l *WSListener) Accept() (net.Conn, error) {
	conn, ok := <-l.connCh
	if !ok {
		return nil, fmt.Errorf("closed")
	}
	return conn, nil
}

func (l *WSListener) Addr() net.Addr { return l.ln.Addr() }
func (l *WSListener) Close() error   { close(l.connCh); return l.ln.Close() }
