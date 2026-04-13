package nrtp

import (
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// UTLSFingerprint 支持的指纹
var utlsFingerprints = map[string]*utls.ClientHelloID{
	"chrome":     &utls.HelloChrome_Auto,
	"firefox":    &utls.HelloFirefox_Auto,
	"safari":     &utls.HelloSafari_Auto,
	"edge":       &utls.HelloEdge_Auto,
	"ios":        &utls.HelloIOS_Auto,
	"android":    &utls.HelloAndroid_11_OkHttp,
	"random":     &utls.HelloRandomized,
	"randomized": &utls.HelloRandomizedALPN,
}

// DialUTLS 使用指定指纹的TLS连接
// fingerprint: chrome/firefox/safari/edge/ios/android/random
func DialUTLS(addr, sni string, fingerprints ...string) (net.Conn, error) {
	fp := "chrome"
	if len(fingerprints) > 0 && fingerprints[0] != "" {
		fp = fingerprints[0]
	}

	helloID, ok := utlsFingerprints[fp]
	if !ok {
		return nil, fmt.Errorf("unknown fingerprint: %s (available: chrome/firefox/safari/edge/ios/android/random)", fp)
	}

	rawConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	config := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}

	uConn := utls.UClient(rawConn, config, *helloID)
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	return uConn, nil
}

// ListFingerprints 返回所有支持的指纹名
func ListFingerprints() []string {
	names := make([]string, 0, len(utlsFingerprints))
	for k := range utlsFingerprints {
		names = append(names, k)
	}
	return names
}
