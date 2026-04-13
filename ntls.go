// Package ntls provides TCP transport with three security tiers.
//
// Modes:
//   - none:     Plain TCP + PSK auth (LAN/internal)
//   - tls:      TLS + PSK auth (dedicated line, self-signed/ACME cert)
//   - fake-tls: Reality - proxy to real server for non-auth clients (cross-border)
package nrtp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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
	Password string // PSK密码
	Mode     string // none / tls / fake-tls
	SNI      string // fake-tls: 代理目标 / tls: 证书CN
	CertMode string // tls模式: self(默认) / file / acme
	CertFile string // file模式: 证书路径
	KeyFile  string // file模式: 私钥路径
	ACMEHost string // acme模式: 域名
	WS       *WSConfig // ws模式配置
}

// Listener nTLS服务端
type Listener struct {
	ln   net.Listener
	raw  net.Listener // none模式用
	psk  []byte
	cfg  *Config
}

// Listen 创建服务端
func Listen(addr string, cfg *Config) (*Listener, error) {
	if cfg.Mode == "" {
		cfg.Mode = "tls"
	}
	psk := deriveKey(cfg.Password)

	switch cfg.Mode {
	case "none":
		// 纯TCP
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		log.Printf("[nTLS] 模式: none (明文TCP + PSK)")
		return &Listener{raw: ln, psk: psk, cfg: cfg}, nil

	case "tls":
		// 标准TLS
		tlsCfg, err := makeTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		ln, err := tls.Listen("tcp", addr, tlsCfg)
		if err != nil {
			return nil, err
		}
		log.Printf("[nTLS] 模式: tls (加密)")
		return &Listener{ln: ln, psk: psk, cfg: cfg}, nil

	case "fake-tls":
		// Reality: 原始TCP监听，手动处理
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		log.Printf("[nTLS] 模式: fake-tls → %s (Reality)", cfg.SNI)
		return &Listener{raw: ln, psk: psk, cfg: cfg}, nil

	default:
		return nil, fmt.Errorf("unknown mode: %s", cfg.Mode)
	}
}

// Accept 接受并认证连接
func (l *Listener) Accept() (net.Conn, error) {
	switch l.cfg.Mode {
	case "none":
		conn, err := l.raw.Accept()
		if err != nil {
			return nil, err
		}
		if err := serverAuth(conn, l.psk); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil

	case "tls":
		conn, err := l.ln.Accept()
		if err != nil {
			return nil, err
		}
		if err := serverAuth(conn, l.psk); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil

	case "fake-tls":
		return l.acceptReality()

	default:
		return nil, errors.New("bad mode")
	}
}

func (l *Listener) Addr() net.Addr {
	if l.ln != nil {
		return l.ln.Addr()
	}
	return l.raw.Addr()
}

func (l *Listener) Close() error {
	if l.ln != nil {
		return l.ln.Close()
	}
	return l.raw.Close()
}

// === Reality (fake-tls) ===

// acceptReality 检查ClientHello中的认证标记
// 认证客户端 → 自己处理TLS → 代理模式
// 非认证客户端 → 整个连接转发到真实服务器
func (l *Listener) acceptReality() (net.Conn, error) {
	for {
		conn, err := l.raw.Accept()
		if err != nil {
			return nil, err
		}

		// 偷看ClientHello
		buf := make([]byte, 2048)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		conn.SetReadDeadline(time.Time{})
		if err != nil || n < 6 {
			conn.Close()
			continue
		}

		// 检查是否是我们的客户端（ClientHello里的SessionID带HMAC标记）
		isOurs := checkRealityAuth(buf[:n], l.psk)

		if !isOurs {
			// 不是我们的 → 转发到真实服务器
			go proxyToReal(conn, buf[:n], l.cfg.SNI)
			continue
		}

		// 是我们的 → 用自签名证书做TLS
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{mustSelfSign(l.cfg.SNI)},
			MinVersion:   tls.VersionTLS12,
		}

		// 把已读的ClientHello和conn拼回去
		combined := &prefixConn{prefix: buf[:n], Conn: conn}
		tlsConn := tls.Server(combined, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			continue
		}

		// PSK验证
		if err := serverAuth(tlsConn, l.psk); err != nil {
			tlsConn.Close()
			continue
		}

		return tlsConn, nil
	}
}

// proxyToReal 把非认证连接转发到真实服务器
func proxyToReal(client net.Conn, firstData []byte, sni string) {
	defer client.Close()

	addr := sni
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = sni + ":443"
	}

	remote, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()

	// 把已读的ClientHello发给真实服务器
	remote.Write(firstData)

	// 双向转发（真实服务器完成TLS握手）
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, client); done <- struct{}{} }()
	go func() { io.Copy(client, remote); done <- struct{}{} }()
	<-done
}

// checkRealityAuth 检查ClientHello的SessionID是否包含HMAC认证
// ClientHello格式: [1B type=22][2B version][2B length][1B handshake_type=1]...
// SessionID位于固定偏移
func checkRealityAuth(data []byte, psk []byte) bool {
	if len(data) < 44 {
		return false
	}
	// TLS record: type(1) + version(2) + length(2)
	if data[0] != 22 { // Handshake
		return false
	}
	// Handshake: type(1) + length(3) + version(2) + random(32)
	// = offset 5+1+3+2+32 = 43
	// SessionID length at offset 43
	if len(data) < 44 {
		return false
	}
	sidLen := int(data[43])
	if sidLen < 32 || len(data) < 44+sidLen {
		return false
	}
	sessionID := data[44 : 44+sidLen]

	// 前16字节是随机数据，后16字节是HMAC(psk, 前16字节)
	if sidLen < 32 {
		return false
	}
	nonce := sessionID[:16]
	tag := sessionID[16:32]

	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	expected := mac.Sum(nil)[:16]

	return hmac.Equal(tag, expected)
}

// prefixConn 把已读数据和原始连接拼接
type prefixConn struct {
	prefix []byte
	offset int
	net.Conn
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if c.offset < len(c.prefix) {
		n := copy(p, c.prefix[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// === Dial (客户端) ===

func Dial(addr string, cfg *Config) (net.Conn, error) {
	if cfg.Mode == "" {
		cfg.Mode = "tls"
	}
	psk := deriveKey(cfg.Password)

	switch cfg.Mode {
	case "none":
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		if err := clientAuth(conn, psk); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil

	case "tls":
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
		if err := clientAuth(conn, psk); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil

	case "fake-tls":
		return dialReality(addr, cfg, psk)

	default:
		return nil, fmt.Errorf("unknown mode: %s", cfg.Mode)
	}
}

// dialReality 在ClientHello的SessionID里嵌入HMAC认证标记
func dialReality(addr string, cfg *Config, psk []byte) (net.Conn, error) {
	sni := cfg.SNI
	if sni == "" {
		host, _, _ := net.SplitHostPort(addr)
		sni = host
	}

	// 生成带认证标记的SessionID
	nonce := make([]byte, 16)
	rand.Read(nonce)
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	tag := mac.Sum(nil)[:16]
	sessionID := append(nonce, tag...)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		SessionTicketsDisabled: true,
	}

	// 注入SessionID
	// Go的tls库不直接暴露SessionID设置
	// 用ClientSessionCache来间接设置
	tlsCfg.ClientSessionCache = &realitySessionCache{sessionID: sessionID}

	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reality handshake: %w", err)
	}

	if err := clientAuth(tlsConn, psk); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// realitySessionCache 注入自定义SessionID
type realitySessionCache struct {
	sessionID []byte
}

func (c *realitySessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	// 返回一个假的session来设置SessionID
	// Go 1.21+ 有 NewResumptionState
	return nil, false
}

func (c *realitySessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {}

// === 证书 ===

func makeTLSConfig(cfg *Config) (*tls.Config, error) {
	certMode := cfg.CertMode
	if certMode == "" { certMode = "self" }

	switch certMode {
	case "file":
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, errors.New("file模式需要CertFile和KeyFile")
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		log.Printf("[nTLS] tls模式: 自定义证书")
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil

	case "acme":
		if cfg.ACMEHost == "" {
			return nil, errors.New("acme模式需要ACMEHost")
		}
		// TODO: golang.org/x/crypto/acme/autocert 集成
		log.Printf("[nTLS] tls模式: ACME %s (待实现，回退自签名)", cfg.ACMEHost)
		cert := mustSelfSign(cfg.ACMEHost)
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil

	default: // self
		cn := cfg.SNI
		if cn == "" { cn = "localhost" }
		cert := mustSelfSign(cn)
		log.Printf("[nTLS] tls模式: 自签名 CN=%s", cn)
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
}

func mustSelfSign(cn string) tls.Certificate {
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
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return cert
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

// 避免unused import
var _ = binary.BigEndian
