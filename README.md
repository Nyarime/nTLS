# NRTP

**Naixi Reliable TCP Protocol**

[![Go Reference](https://pkg.go.dev/badge/github.com/nyarime/nrtp.svg)](https://pkg.go.dev/github.com/nyarime/nrtp)

TCP 传输协议，fake-tls 证书克隆 + WebSocket 伪装 + PSK 认证。[NRUP](https://github.com/Nyarime/NRUP) 的 TCP 对应。

[English](#english)

## 安装

```bash
go get github.com/nyarime/nrtp@v1.0.0
```

## 协议对比

| | NRUP | NRTP |
|---|---|---|
| 传输层 | UDP | TCP |
| 加密 | nDTLS | nTLS |
| 丢包恢复 | FEC + ARQ | TCP 重传 |
| 伪装 | AnyConnect DTLS / QUIC | fake-tls / WebSocket |
| 适用 | 实时/游戏/弱网 | 网页/下载/CDN |

组合使用 = [NekoPass](https://github.com/Nyarime/NekoPass-Lite) 完整传输层。

## 四种模式

| 模式 | 说明 | 场景 |
|------|------|------|
| `none` | 明文 TCP + PSK | 内网 |
| `tls` | TLS + PSK (自签/文件/ACME) | 专线 |
| `fake-tls` | Reality 风格，代理到真实服务器 | 过墙 |
| `ws` | WebSocket Binary Frame + PSK | CDN 友好 |

## 快速开始

```go
import "github.com/nyarime/nrtp"

// 服务端
cfg := &nrtp.Config{Password: "secret", Mode: "tls"}
listener, _ := nrtp.Listen(":443", cfg)
conn, _ := listener.Accept()

// 客户端
conn, _ := nrtp.Dial("server:443", cfg)
conn.Write([]byte("hello"))
```

## fake-tls (Reality)

```go
// 服务端：非认证访问转发到真实 VPN 服务器
cfg := &nrtp.Config{
    Password: "secret",
    Mode:     "fake-tls",
    SNI:      "vpn2fa.hku.hk",
}
listener, _ := nrtp.Listen(":443", cfg)
```

## WebSocket

```go
cfg := &nrtp.Config{
    Password: "secret",
    Mode:     "ws",
    WS:       &nrtp.WSConfig{Path: "/api/ws"},
}
// CDN (Cloudflare) 友好
```

## 许可证

Apache License 2.0

---

<a name="english"></a>
## English

**Naixi Reliable TCP Protocol**

TCP transport with fake-tls certificate cloning, WebSocket disguise, and PSK auth. TCP counterpart to [NRUP](https://github.com/Nyarime/NRUP).

```bash
go get github.com/nyarime/nrtp@v1.0.0
```

Modes: `none` (plain) / `tls` (encrypted) / `fake-tls` (Reality) / `ws` (WebSocket)
