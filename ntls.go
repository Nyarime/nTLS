// Package ntls provides TCP transport with three security tiers.
//
// Modes:
//   - none:     Plain TCP + PSK auth (LAN/internal)
//   - tls:      TLS + PSK auth (dedicated line, self-signed/ACME cert)
//   - fake-tls: fake-tls - proxy to real server for non-auth clients (cross-border)
package nrtp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"golang.org/x/crypto/acme/autocert"
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
	Password string    // PSK密码
	Mode     string    // none / tls / fake-tls / ws
	SNI      string    // fake-tls: 代理目标 / tls: 证书CN
	CertMode string    // tls模式: self(默认) / file / acme
	CertFile string    // file模式: 证书路径
	KeyFile  string    // file模式: 私钥路径
	ACMEHost string    // acme模式: 域名
	WS       *WSConfig // ws模式配置

	// Pro 特性
	UseUTLS    bool      // 客户端用Chrome指纹TLS
	UTLSFingerprint string // chrome(默认)/firefox/safari/edge/ios/android/random
	FallbackCfg *Fallback // 回落配置 (portal/proxy/static)
}

// Listener nTLS服务端
type Listener struct {
	ln   net.Listener
	raw  net.Listener // none模式用
	psk  []byte
	cert tls.Certificate
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
		// fake-tls: 原始TCP监听，手动处理
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		log.Printf("[nTLS] 模式: fake-tls → %s (fake-tls)", cfg.SNI)
		return &Listener{raw: ln, psk: psk, cfg: cfg, cert: mustSelfSign(cfg.SNI)}, nil
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
		return l.acceptFakeTLS()

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

// === fake-tls (fake-tls) ===

// acceptFakeTLS 检查ClientHello中的认证标记
// 认证客户端 → 自己处理TLS → 代理模式
// 非认证客户端 → 整个连接转发到真实服务器
func (l *Listener) acceptFakeTLS() (net.Conn, error) {
	for {
		conn, err := l.raw.Accept()
		if err != nil {
			return nil, err
		}

		// Peek前5字节判断TLS ClientHello
		peekBuf := make([]byte, 5)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := io.ReadFull(conn, peekBuf)
		conn.SetReadDeadline(time.Time{})
		if err != nil || n < 5 {
			conn.Close()
			continue
		}

		// TLS ClientHello: type=22, version>=0x0301, length
		isTLS := peekBuf[0] == 22 && peekBuf[1] >= 3

		if !isTLS {
			// 非TLS流量 → 直接转发到真实服务器（零污染）
			go proxyToRealWithData(conn, peekBuf[:n], l.cfg.SNI)
			continue
		}

		// 是TLS → 拼回已读数据 + 做自己的TLS握手
		prefixed := &prefixConn{prefix: peekBuf[:n], Conn: conn}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{l.cert},
			MinVersion:   tls.VersionTLS12,
		}
		tlsConn := tls.Server(prefixed, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			// TLS握手失败 → 转发到真实服务器
			conn.Close()
			continue
		}

		// PSK认证
		if err := serverAuth(tlsConn, l.psk); err != nil {
			if l.cfg.FallbackCfg != nil {
				go l.cfg.FallbackCfg.Handle(tlsConn)
			} else {
				tlsConn.Close()
			}
			continue
		}

		return tlsConn, nil
	}
}

// prefixConn 把已读数据拼回连接前面
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

// proxyToRealWithData 转发到真实服务器（带已读数据）
func proxyToRealWithData(client net.Conn, firstData []byte, sni string) {
	defer client.Close()
	addr := sni
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = sni + ":443"
	}
	remote, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil { log.Printf("[NRTP] proxy to %s failed: %v", addr, err); return }
	defer remote.Close()
	remote.Write(firstData)
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, client); done <- struct{}{} }()
	go func() { io.Copy(client, remote); done <- struct{}{} }()
	<-done
}

// proxyToReal 转发非TLS连接到真实服务器

// checkfake-tlsAuth 检查ClientHello的SessionID是否包含HMAC认证
// ClientHello格式: [1B type=22][2B version][2B length][1B handshake_type=1]...
// SessionID位于固定偏移

// prefixConn 把已读数据和原始连接拼接


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
		var conn net.Conn
		var err error
		if cfg.UseUTLS {
			conn, err = DialUTLS(addr, sni, cfg.UTLSFingerprint)
		} else {
			conn, err = tls.Dial("tcp", addr, &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true,
			})
		}
		if err != nil {
			return nil, err
		}
		if err := clientAuth(conn, psk); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil

	case "fake-tls":
		return dialFakeTLS(addr, cfg, psk)

	default:
		return nil, fmt.Errorf("unknown mode: %s", cfg.Mode)
	}
}

// dialFakeTLS 在ClientHello的SessionID里嵌入HMAC认证标记
func dialFakeTLS(addr string, cfg *Config, psk []byte) (net.Conn, error) {
	sni := cfg.SNI
	if sni == "" {
		host, _, _ := net.SplitHostPort(addr)
		sni = host
	}
	var conn net.Conn
	var err error
	if cfg.UseUTLS {
		conn, err = DialUTLS(addr, sni, cfg.UTLSFingerprint)
	} else {
		conn, err = tls.Dial("tcp", addr, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		})
	}
	if err != nil {
		return nil, err
	}
	if err := clientAuth(conn, psk); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
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
	if subtle.ConstantTimeCompare(buf, expected[:]) != 1 {
		return errors.New("bad psk")
	}
	conn.Write([]byte{0x01})
	return nil
}

// 避免unused import

func makeTLSConfig(cfg *Config) (*tls.Config, error) {
	certMode := cfg.CertMode
	if certMode == "" { certMode = "self" }

	switch certMode {
	case "file":
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, errors.New("file模式需要CertFile和KeyFile")
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil { return nil, err }
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	case "acme":
		host := cfg.ACMEHost
		if host == "" { host = cfg.SNI }
		if host == "" { return nil, errors.New("acme需要ACMEHost或SNI") }
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(host),
			Cache:      autocert.DirCache(".nrtp-certs"),
		}
		log.Printf("[NRTP] ACME: %s", host)
		return m.TLSConfig(), nil
	default:
		cn := cfg.SNI
		if cn == "" { cn = "localhost" }
		cert := mustSelfSign(cn)
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
}
