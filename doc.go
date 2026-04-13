// Package nrtp provides TCP transport with fake-tls, WebSocket, and PSK auth.
// TCP counterpart to NRUP (UDP).
//
// Modes:
//   - none:     Plain TCP + PSK (LAN/internal)
//   - tls:      TLS + PSK (dedicated line)
//   - fake-tls: Peek + proxy to real server for non-auth (cross-border)
//   - ws:       WebSocket over TLS (CDN friendly)
//
// Pro features:
//   - UseUTLS:     Chrome fingerprint TLS
//   - FallbackCfg: Portal/proxy/static fallback
//   - SmartTransport: UDP/TCP auto-switch
//   - AutoFallback: Primary/secondary with auto-recovery
//   - FetchCert:   Remote TLS certificate retrieval
//   - DialUTLS:    Chrome-fingerprinted TLS dial
package nrtp
