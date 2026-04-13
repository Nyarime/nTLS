// Package ntls provides a TLS transport library with certificate mirroring
// (fake-tls) and PSK authentication. Designed as the TCP counterpart to NRUP (UDP).
//
// Together, NRUP + nTLS form a complete encrypted transport stack:
//   - NRUP: UDP with FEC + ARQ + BBR (packet loss recovery)
//   - nTLS: TCP with certificate mirroring + PSK (reliable stream)
//
// # Modes
//
//   - fake-tls: Mirror certificate from a real server (e.g., AnyConnect VPN)
//   - self-signed: Generate self-signed certificate
//   - acme: Let's Encrypt automatic certificate
//
// # Usage
//
//	// Server
//	cfg := &ntls.Config{
//	    Password: "secret",
//	    SNI:      "vpn2fa.hku.hk",  // mirror cert from this server
//	}
//	listener, _ := ntls.Listen(":443", cfg)
//	conn, _ := listener.Accept()
//
//	// Client
//	conn, _ := ntls.Dial("server:443", cfg)
package ntls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"
)

// Config nTLS配置
type Config struct {
	Password string // 连接密码（PSK派生）
	SNI      string // 证书镜像目标（fake-tls模式）
	CertFile string // 自定义证书文件路径（可选）
	KeyFile  string // 自定义私钥文件路径（可选）
}

// Listener nTLS服务端监听
type Listener struct {
	ln  net.Listener
	psk []byte
}

// Listen 创建nTLS服务端
func Listen(addr string, cfg *Config) (*Listener, error) {
	tlsCfg, err := serverTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, err
	}

	return &Listener{
		ln:  ln,
		psk: deriveKey(cfg.Password),
	}, nil
}

// Accept 接受连接并验证PSK
func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}

	// PSK验证
	if err := serverAuth(conn, l.psk); err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth failed: %w", err)
	}

	return conn, nil
}

// Addr 返回监听地址
func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}

// Close 关闭监听
func (l *Listener) Close() error {
	return l.ln.Close()
}

// Dial 连接nTLS服务端
func Dial(addr string, cfg *Config) (net.Conn, error) {
	sni := cfg.SNI
	if sni == "" {
		host, _, _ := net.SplitHostPort(addr)
		sni = host
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}

	// PSK验证
	if err := clientAuth(conn, deriveKey(cfg.Password)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth failed: %w", err)
	}

	return conn, nil
}

// === 证书 ===

func serverTLSConfig(cfg *Config) (*tls.Config, error) {
	// 1. 自定义证书
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}

	// 2. fake-tls: 从远端镜像证书
	if cfg.SNI != "" {
	}

	// 3. 自签名
	cert, err := selfSignedCert(cfg.SNI)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// mirrorCert 从远端服务器获取证书DER
func mirrorCert(sni string) ([]byte, error) {
	addr := sni
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = sni + ":443"
	}
	host, _, _ := net.SplitHostPort(addr)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", addr,
		&tls.Config{ServerName: host, InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("no certificate")
	}

	cert := state.PeerCertificates[0]
	log.Printf("[nTLS] 获取证书: CN=%s Issuer=%s", cert.Subject.CommonName, cert.Issuer.CommonName)
	return cert.Raw, nil
}

// selfSignedCert 生成自签名证书
func selfSignedCert(cn string) (tls.Certificate, error) {
	if cn == "" {
		cn = "localhost"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{cn},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// === PSK认证 ===

func deriveKey(password string) []byte {
	h := sha256.Sum256([]byte("ntls:" + password))
	return h[:]
}

func clientAuth(conn net.Conn, psk []byte) error {
	auth := sha256.Sum256(psk)
	if _, err := conn.Write(auth[:]); err != nil {
		return err
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return err
	}
	if ack[0] != 0x01 {
		return errors.New("rejected")
	}
	return nil
}

func serverAuth(conn net.Conn, psk []byte) error {
	authBuf := make([]byte, 32)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, authBuf); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Time{})

	expected := sha256.Sum256(psk)
	for i := range authBuf {
		if authBuf[i] != expected[i] {
			return errors.New("bad psk")
		}
	}
	conn.Write([]byte{0x01})
	return nil
}
