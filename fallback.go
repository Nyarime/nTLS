package nrtp

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// Fallback 统一回落处理（非认证连接的响应）
type Fallback struct {
	Mode   string // portal / proxy / static
	Target string // proxy: 反代目标地址
	Host   string // proxy: 自定义Host头
	HTML   string // static: 自定义HTML
}

// Handle 处理非认证连接
func (f *Fallback) Handle(conn net.Conn) {
	defer conn.Close()

	switch f.Mode {
	case "proxy":
		// 反向代理到后端
		target := f.Target
		if target == "" {
			return
		}
		backend, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer backend.Close()
		done := make(chan struct{}, 2)
		go func() { io.Copy(backend, conn); done <- struct{}{} }()
		go func() { io.Copy(conn, backend); done <- struct{}{} }()
		<-done

	case "static":
		body := f.HTML
		if body == "" {
			body = "<html><body>OK</body></html>"
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n" + body))

	default: // portal
		PortalFallback(conn)
	}
}

// NewReverseProxyHandler HTTP反向代理handler
func NewReverseProxyHandler(target, host string) http.Handler {
	targetURL, err := url.Parse("http://" + target)
	if err != nil {
		log.Printf("[NRTP] 反代目标解析失败: %v", err)
		return http.NotFoundHandler()
	}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		if host != "" {
			req.Host = host
		}
	}
	return proxy
}
