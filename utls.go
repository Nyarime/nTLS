package nrtp

import (
	"net"

	utls "github.com/refraction-networking/utls"
)

// DialUTLS 使用Chrome指纹的TLS连接（DPI无法区分真实浏览器）
func DialUTLS(addr, sni string) (net.Conn, error) {
	rawConn, err := net.DialTimeout("tcp", addr, 10*1e9)
	if err != nil {
		return nil, err
	}

	config := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}

	uConn := utls.UClient(rawConn, config, utls.HelloChrome_Auto)
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	return uConn, nil
}
