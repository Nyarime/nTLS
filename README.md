# NRTP

[![Go Reference](https://pkg.go.dev/badge/github.com/nyarime/nrtp.svg)](https://pkg.go.dev/github.com/nyarime/nrtp)

TCP 传输协议。fake-tls 伪装 + WebSocket + XHTTP + PSK 认证。[NRUP](https://github.com/Nyarime/NRUP) 的 TCP 对应。

[English](#english)

## 安装

```bash
go get github.com/nyarime/nrtp@v1.4.3
```

## 五种模式

| 模式 | 加密 | 伪装 | 场景 |
|------|------|------|------|
| `none` | ❌ | ❌ | 内网 |
| `tls` | ✅ | 自签名/ACME | 专线 |
| `fake-tls` | ✅ | Zero-Byte Reality | 过墙（推荐） |
| `ws` | ✅ | WebSocket over TLS | CDN |
| `xhttp` | ✅ | HTTP streaming | CF CDN |

## 快速开始

### fake-tls（推荐，Zero-Byte Reality）

```go
cfg := &nrtp.Config{
    Password: "secret",
    Mode:     "fake-tls",
    SNI:      "vpn2fa.hku.hk",
    UseUTLS:  true,
}

// 服务端
listener, _ := nrtp.Listen(":443", cfg)
conn, _ := listener.Accept()
defer conn.Close()
buf := make([]byte, 4096)
n, _ := conn.Read(buf)
conn.Write(buf[:n])

// 客户端
conn, _ := nrtp.Dial("server:443", cfg)
defer conn.Close()
conn.Write([]byte("hello"))
n, _ := conn.Read(buf)
```

### TLS（专线加密）

```go
// 服务端
listener, _ := nrtp.Listen(":443", &nrtp.Config{
    Password: "secret", Mode: "tls",
})
conn, _ := listener.Accept()

// 客户端
conn, _ := nrtp.Dial("server:443", &nrtp.Config{
    Password: "secret", Mode: "tls",
})
```

### WebSocket（CDN 友好）

```go
// 服务端
listener, _ := nrtp.ListenWS(":443", &nrtp.Config{
    Password: "secret", Mode: "ws",
    WS: &nrtp.WSConfig{Path: "/ws"},
})
conn, _ := listener.Accept()

// 客户端
conn, _ := nrtp.DialWS("server:443", &nrtp.Config{
    Password: "secret", Mode: "ws",
    WS: &nrtp.WSConfig{Path: "/ws", SNI: "ws.example.com"},
})
```

### XHTTP（CF CDN）

```go
// 服务端
listener, _ := nrtp.ListenXHTTP(":443", &nrtp.Config{
    Password: "secret", Mode: "xhttp",
    XHTTP: &nrtp.XHTTPConfig{Path: "/stream"},
})

// 客户端
conn, _ := nrtp.DialXHTTP("server:443", &nrtp.Config{
    Password: "secret", Mode: "xhttp",
    XHTTP: &nrtp.XHTTPConfig{Path: "/stream"},
})
```

### none（内网）

```go
listener, _ := nrtp.Listen(":4000", &nrtp.Config{
    Password: "secret", Mode: "none",
})
conn, _ := nrtp.Dial("server:4000", &nrtp.Config{
    Password: "secret", Mode: "none",
})
```

## Zero-Byte Reality

认证信息藏入 TLS ClientHello SessionID（零额外字节）：

```
客户端 → SessionID[0:16] = HMAC(PSK, timestamp)
服务端 → 解析SessionID → 验证HMAC + ±90秒时间窗
  匹配 → 自签名TLS + 代理
  不匹配 → 转发到真实服务器（真实证书）
```

GFW 主动探测看到：真实服务器的真实证书。

## Cloudflare CDN

```go
// 服务端 (域名开CF橙色云朵)
listener, _ := nrtp.ListenWS(":443", &nrtp.Config{
    Password: "secret", Mode: "ws",
    CertMode: "acme", ACMEHost: "ws.example.com",
    WS: &nrtp.WSConfig{Path: "/ws"},
})

// 客户端
conn, _ := nrtp.DialWS("ws.example.com:443", &nrtp.Config{
    Password: "secret", Mode: "ws",
    WS: &nrtp.WSConfig{Path: "/ws", SNI: "ws.example.com"},
})
```

## NRUP + NRTP

| | NRUP | NRTP |
|---|---|---|
| 传输层 | UDP | TCP |
| 加密 | nDTLS | TLS |
| 丢包恢复 | FEC + ARQ | TCP 重传 |
| 伪装 | AnyConnect / QUIC | fake-tls / WS / XHTTP |
| 适用 | 实时/游戏/弱网 | 网页/下载/CDN |

组合使用 = [NekoPass Lite](https://github.com/Nyarime/NekoPass-Lite)

## 许可证

Apache License 2.0

---

<a name="english"></a>
## English

TCP transport with Zero-Byte Reality, WebSocket, XHTTP, and PSK auth. TCP counterpart to [NRUP](https://github.com/Nyarime/NRUP).

```bash
go get github.com/nyarime/nrtp@v1.4.3
```

Five modes: `none` / `tls` / `fake-tls` (Zero-Byte Reality) / `ws` / `xhttp`

Each mode supports both server (`Listen`) and client (`Dial`).
