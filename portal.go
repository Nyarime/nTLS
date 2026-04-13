package nrtp

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// AnyConnect Portal 回落页面
const portalHTML = `<!DOCTYPE html>
<html>
<head>
<title>SSL VPN Service</title>
<style>
body{font-family:Arial,sans-serif;background:#f5f5f5;margin:0}
.header{background:#00467f;color:#fff;padding:12px 24px;font-size:18px}
.content{max-width:420px;margin:60px auto;background:#fff;border:1px solid #ccc;border-radius:4px;padding:32px}
h2{color:#333;margin:0 0 20px}
label{display:block;margin:8px 0 4px;color:#555;font-size:13px}
input[type=text],input[type=password]{width:100%%;box-sizing:border-box;padding:8px;border:1px solid #ccc;border-radius:3px}
select{width:100%%;padding:8px;border:1px solid #ccc;border-radius:3px}
.btn{background:#00467f;color:#fff;border:none;padding:10px;border-radius:3px;cursor:pointer;width:100%%;margin-top:16px}
.footer{text-align:center;color:#999;font-size:11px;margin-top:24px}
</style>
</head>
<body>
<div class="header">Cisco SSL VPN Service</div>
<div class="content">
<h2>AnyConnect Login</h2>
<form>
<label>GROUP:</label>
<select><option>DefaultWEBVPNGroup</option></select>
<label>USERNAME:</label>
<input type="text" placeholder="username">
<label>PASSWORD:</label>
<input type="password" placeholder="password">
<button class="btn" type="button" onclick="alert('Use AnyConnect client')">Login</button>
</form>
<div class="footer">Adaptive Security Appliance</div>
</div>
</body>
</html>`

// NewPortalHandler 返回Cisco ASA风格的HTTP handler（回落用）
func NewPortalHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Cisco ASDM")
		w.Header().Set("X-Powered-By", "ASA")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")

		path := r.URL.Path
		if strings.HasPrefix(path, "/+CSCOE+/") ||
			strings.HasPrefix(path, "/CSCOSSLC/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, portalHTML)
	})
}

// PortalFallback 非TLS连接的回落处理
func PortalFallback(conn net.Conn) {
	defer conn.Close()
	body := portalHTML
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Server: Cisco ASDM\r\n"+
		"Content-Type: text/html\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n\r\n%s", len(body), body)
	conn.Write([]byte(resp))
}
