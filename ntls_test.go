package ntls

import "testing"

func TestDialListen(t *testing.T) {
	cfg := &Config{Password: "test123"}

	listener, err := Listen(":0", cfg)
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

	conn, err := Dial(listener.Addr().String(), cfg)
	if err != nil { t.Fatal(err) }
	defer conn.Close()

	conn.Write([]byte("hello-ntls"))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)

	if string(buf[:n]) != "hello-ntls" {
		t.Fatalf("mismatch: %q", string(buf[:n]))
	}
	t.Logf("✅ nTLS echo OK")
}

func TestFakeTLS(t *testing.T) {
	cfg := &Config{Password: "test", SNI: "vpn2fa.hku.hk"}

	listener, err := Listen(":0", cfg)
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			conn.Write(buf[:n])
		}
	}()

	conn, err := Dial(listener.Addr().String(), &Config{Password: "test"})
	if err != nil { t.Fatal(err) }
	defer conn.Close()

	conn.Write([]byte("fake-tls-ok"))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)

	if string(buf[:n]) != "fake-tls-ok" {
		t.Fatalf("mismatch: %q", string(buf[:n]))
	}
	t.Logf("✅ fake-tls (cert mirrored from vpn2fa.hku.hk)")
}
