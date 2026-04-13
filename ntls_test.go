package nrtp

import (
	"testing"
	"time"
)

func TestModeNone(t *testing.T) {
	cfg := &Config{Password: "test", Mode: "none"}
	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn == nil { return }
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	conn, err := Dial(listener.Addr().String(), &Config{Password: "test", Mode: "none"})
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	conn.Write([]byte("plain-tcp"))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "plain-tcp" { t.Fatalf("got: %q", string(buf[:n])) }
	t.Log("✅ none模式 (明文TCP + PSK)")
}

func TestModeTLS(t *testing.T) {
	cfg := &Config{Password: "test", Mode: "tls"}
	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn == nil { return }
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	conn, err := Dial(listener.Addr().String(), &Config{Password: "test", Mode: "tls"})
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	conn.Write([]byte("encrypted-tls"))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "encrypted-tls" { t.Fatalf("got: %q", string(buf[:n])) }
	t.Log("✅ tls模式 (加密)")
}

func TestModeWS(t *testing.T) {
	cfg := &Config{
		Password: "test",
		Mode:     "ws",
		WS:       &WSConfig{Path: "/tunnel"},
	}

	listener, err := ListenWS(":0", cfg)
	time.Sleep(500 * time.Millisecond)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil { return }
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	conn, err := DialWS(listener.Addr().String(), cfg)
	if err != nil { t.Fatal(err) }
	defer conn.Close()

	conn.Write([]byte("websocket-tunnel"))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)

	if string(buf[:n]) != "websocket-tunnel" {
		t.Fatalf("got: %q", string(buf[:n]))
	}
	t.Log("✅ ws模式 (WebSocket over TLS)")
}
