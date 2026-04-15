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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"crypto/subtle"
	"crypto/tls"
	utls "github.com/refraction-networking/utls"
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
	Mode     string    // none / tls / fake-tls / ws / xhttp
	SNI      string    // fake-tls: 代理目标 / tls: 证书CN
	CertMode string    // tls模式: self(默认) / file / acme
	CertFile string    // file模式: 证书路径
	KeyFile  string    // file模式: 私钥路径
	ACMEHost string    // acme模式: 域名
	WS       *WSConfig // ws模式配置
	XHTTP    *XHTTPConfig // xhttp模式配置

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

	// v1.4.1: PSK校验 + 启动日志
	if len(cfg.Password) < 8 {
		log.Printf("[NRTP] ⚠️ WARNING: 密码过短(%d字符)，推荐≥32字节: openssl rand -hex 32", len(cfg.Password))
	}
	if len(cfg.Password) == 0 {
		return nil, errors.New("密码不能为空")
	}
	log.Printf("[NRTP] 启动 mode=%s addr=%s psk=%dB", cfg.Mode, addr, len(cfg.Password))
	if cfg.UseUTLS {
		fp := cfg.UTLSFingerprint; if fp == "" { fp = "chrome" }
		log.Printf("[NRTP] uTLS=%s", fp)
	}

	psk := deriveKey(cfg.Password)

	// v1.4.2: 配置校验
	switch cfg.Mode {
	case "fake-tls":
		if cfg.SNI == "" { return nil, errors.New("fake-tls需要SNI") }
	case "ws":
		if cfg.WS == nil || cfg.WS.Path == "" { return nil, errors.New("ws需要WS.Path") }
	case "xhttp":
		if cfg.XHTTP == nil || cfg.XHTTP.Path == "" { return nil, errors.New("xhttp需要XHTTP.Path") }
	}

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
// realityKnock 生成暗号(前3字节PSK派生)
// realitySignal 生成16字节认证信号（timestamp+HMAC防重放）
// 前8字节: unix timestamp (大端序)
// 后8字节: HMAC-SHA256(PSK, "nrtp:" + timestamp)[:8]
func realitySignal(psk []byte) []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("nrtp:"))
	mac.Write(ts)
	sig := make([]byte, 16)
	copy(sig[:8], ts)
	copy(sig[8:], mac.Sum(nil)[:8])
	return sig
}

// verifyRealitySignal 验证信号（±90秒时间窗）
func verifyRealitySignal(signal, psk []byte) bool {
	if len(signal) < 16 { return false }
	ts := int64(binary.BigEndian.Uint64(signal[:8]))
	now := time.Now().Unix()
	if now-ts > 300 || ts-now > 300 { return false }
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("nrtp:"))
	mac.Write(signal[:8])
	return subtle.ConstantTimeCompare(mac.Sum(nil)[:8], signal[8:16]) == 1
}

func (l *Listener) acceptFakeTLS() (net.Conn, error) {

	for {
		conn, err := l.raw.Accept()
		if err != nil {
			return nil, err
		}

		// Peek ClientHello + 解析SessionID
		peekBuf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		n := 0
		for n < 44 { // 至少读44字节(TLS header + SessionID offset)
			nn, err := conn.Read(peekBuf[n:])
			if err != nil { break }
			n += nn
		}
		conn.SetReadDeadline(time.Time{})
		if n < 44 {
			conn.Close()
			continue
		}

		// 解析SessionID检查knock
		isOurs := false
		if peekBuf[0] == 22 && peekBuf[5] == 1 { // TLS Handshake + ClientHello
			sidLen := int(peekBuf[43])
			if sidLen >= 16 && 44+sidLen <= n {
				sid := peekBuf[44 : 44+sidLen]
				isOurs = verifyRealitySignal(sid[:16], l.psk)
			}
		}

		log.Printf("[Reality] isOurs=%v n=%d peek[0]=%d", isOurs, n, peekBuf[0])
		if !isOurs {
			if l.cfg.FallbackCfg != nil {
				// v1.5.3: 回落Portal (同端口)
				prefixed := &prefixConn{prefix: peekBuf[:n], Conn: conn}
				tlsCfg := &tls.Config{
					Certificates: []tls.Certificate{l.cert},
					MinVersion:   tls.VersionTLS12,
				}
				tlsConn := tls.Server(prefixed, tlsCfg)
				if err := tlsConn.Handshake(); err == nil {
					go l.cfg.FallbackCfg.Handle(tlsConn)
				} else {
					conn.Close()
				}
			} else {
				go proxyToRealWithData(conn, peekBuf[:n], l.cfg.SNI)
			}
			continue
		}

		// 是我们的 → 拼回数据 + 自签名TLS
		prefixed := &prefixConn{prefix: peekBuf[:n], Conn: conn}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{l.cert},
			MinVersion:   tls.VersionTLS12,
		}
		tlsConn := tls.Server(prefixed, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			continue
		}

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
	if len(cfg.Password) == 0 {
		return nil, errors.New("密码不能为空")
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
	// TCP连接
	rawConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// 零字节Reality: knock藏入ClientHello SessionID
	signal := realitySignal(psk)
	sessionID := make([]byte, 32)
	copy(sessionID[:16], signal)
	rand.Read(sessionID[16:])

	utlsCfg := &utls.Config{
		ServerName: sni, InsecureSkipVerify: true,
	}
	utlsConn := utls.UClient(rawConn, utlsCfg, utls.HelloChrome_Auto)
	// Build → 注入SessionID → MarshalClientHello → HandshakeContext
	if err := utlsConn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, err
	}
	// 在marshaled之前注入SessionID
	hello := utlsConn.HandshakeState.Hello
	hello.SessionId = sessionID
	if err := utlsConn.MarshalClientHello(); err != nil {
		rawConn.Close()
		return nil, err
	}
	if err := utlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	var conn net.Conn = utlsConn
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
	if len(password) < 8 {
		log.Printf("[NRTP] ⚠️ WARNING: 密码过短(<%d字符)，推荐32+字节: openssl rand -hex 32", len(password))
	}
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
		log.Printf("[NRTP] ACME: %s (缓存: .nrtp-certs/)", host)
		return m.TLSConfig(), nil
	default:
		cn := cfg.SNI
		if cn == "" { cn = "localhost" }
		cert := mustSelfSign(cn)
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
}

// checkSessionIDKnock 从ClientHello解析SessionID检查knock
