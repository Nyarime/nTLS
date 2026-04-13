// Package ntls provides a TLS transport library with fake-tls certificate
// cloning and PSK authentication. TCP counterpart to NRUP (UDP).
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

type Config struct {
	Password string
	SNI      string // fake-tls: 克隆此服务器的证书信息
	CertFile string
	KeyFile  string
}

type Listener struct {
	ln  net.Listener
	psk []byte
}

func Listen(addr string, cfg *Config) (*Listener, error) {
	tlsCfg, err := serverTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	return &Listener{ln: ln, psk: deriveKey(cfg.Password)}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	if err := serverAuth(conn, l.psk); err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth: %w", err)
	}
	return conn, nil
}

func (l *Listener) Addr() net.Addr { return l.ln.Addr() }
func (l *Listener) Close() error   { return l.ln.Close() }

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
	if err := clientAuth(conn, deriveKey(cfg.Password)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// === 证书 ===

func serverTLSConfig(cfg *Config) (*tls.Config, error) {
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}

	// fake-tls: 从远端获取证书信息，用自己的密钥重签
	if cfg.SNI != "" {
		cert, err := cloneCert(cfg.SNI)
		if err == nil {
			log.Printf("[nTLS] fake-tls: 克隆证书 CN=%s", cfg.SNI)
			return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
		}
		log.Printf("[nTLS] 克隆失败: %v，使用自签名", err)
	}

	cert, err := selfSignedCert(cfg.SNI)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// cloneCert 连接远端服务器，获取其证书信息，用自己的密钥重签
// DPI看到的证书 Subject/Issuer/SAN/Serial 与真实服务器一致
func cloneCert(sni string) (tls.Certificate, error) {
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
		return tls.Certificate{}, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return tls.Certificate{}, errors.New("no cert")
	}

	real := state.PeerCertificates[0]
	log.Printf("[nTLS] 远端证书: CN=%s Issuer=%s SAN=%v",
		real.Subject.CommonName, real.Issuer.CommonName, real.DNSNames)

	// 用远端证书的信息创建新证书（自己的密钥）
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          real.SerialNumber,
		Subject:               real.Subject,
		Issuer:                real.Issuer,
		NotBefore:             real.NotBefore,
		NotAfter:              real.NotAfter,
		DNSNames:              real.DNSNames,
		IPAddresses:           real.IPAddresses,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func selfSignedCert(cn string) (tls.Certificate, error) {
	if cn == "" { cn = "localhost" }
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{cn},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// === PSK ===

func deriveKey(password string) []byte {
	h := sha256.Sum256([]byte("ntls:" + password))
	return h[:]
}

func clientAuth(conn net.Conn, psk []byte) error {
	auth := sha256.Sum256(psk)
	conn.Write(auth[:])
	ack := make([]byte, 1)
	if _, err := io.ReadFull(conn, ack); err != nil || ack[0] != 0x01 {
		return errors.New("rejected")
	}
	return nil
}

func serverAuth(conn net.Conn, psk []byte) error {
	buf := make([]byte, 32)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Time{})
	expected := sha256.Sum256(psk)
	for i := range buf {
		if buf[i] != expected[i] {
			return errors.New("bad psk")
		}
	}
	conn.Write([]byte{0x01})
	return nil
}
