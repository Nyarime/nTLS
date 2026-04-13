package nrtp

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"
)

// FetchCert 连接目标服务器，获取其TLS证书DER
func FetchCert(target string) ([]byte, error) {
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}

	addr := target
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = target + ":443"
	}
	host, _, _ := net.SplitHostPort(addr)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", addr,
		&tls.Config{ServerName: host, InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificate from %s", addr)
	}

	cert := state.PeerCertificates[0]
	log.Printf("[NRTP] 获取证书: CN=%s Issuer=%s (%d bytes)",
		cert.Subject.CommonName, cert.Issuer.CommonName, len(cert.Raw))

	return cert.Raw, nil
}
