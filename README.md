# NRTP

[![Go Reference](https://pkg.go.dev/badge/github.com/nyarime/nrtp.svg)](https://pkg.go.dev/github.com/nyarime/nrtp)

TCP 传输协议，fake-tls + WebSocket 伪装 + PSK 认证。[NRUP](https://github.com/Nyarime/NRUP) 的 TCP 对应。

[English](#english)

## 安装

```bash
go get github.com/nyarime/nrtp@v1.1.0
```

## 四种模式

| 模式 | 加密 | 伪装 | 场景 |
|------|------|------|------|
| `none` | ❌ | ❌ | 内网/测试 |
| `tls` | ✅ | 自签名/文件/ACME | 专线 |
| `fake-tls` | ✅ | 代理到真实服务器 | 过墙 |
| `ws` | ✅ | WebSocket over TLS | CDN 友好 |

## 快速开始

```go
import "github.com/nyarime/nrtp"

// 服务端（TLS 模式）
listener, _ := nrtp.Listen(":443", &nrtp.Config{
    Password: "secret",
    Mode:     "tls",
})
conn, _ := listener.Accept()

// 客户端
conn, _ := nrtp.Dial("server:443", &nrtp.Config{
    Password: "secret",
    Mode:     "tls",
})
```

## fake-tls

非认证访问转发到真实服务器，DPI 看到真实 VPN 在握手：

```go
cfg := &nrtp.Config{
    Password: "secret",
    Mode:     "fake-tls",
    SNI:      "vpn2fa.hku.hk",
}
```

## WebSocket

CDN (Cloudflare) 友好，伪装为正常 HTTPS WebSocket：

```go
cfg := &nrtp.Config{
    Password: "secret",
    Mode:     "ws",
    WS: &nrtp.WSConfig{
        Path: "/api/ws",
        SNI:  "cdn.example.com",
        Headers: map[string]string{
            "User-Agent": "Mozilla/5.0",
        },
    },
}
```

## NRUP + NRTP

| | NRUP | NRTP |
|---|---|---|
| 传输层 | UDP | TCP |
| 加密 | nDTLS | TLS |
| 丢包恢复 | FEC + ARQ | TCP 重传 |
| 伪装 | AnyConnect / QUIC | fake-tls / WebSocket |
| 适用 | 实时/游戏/弱网 | 网页/下载/CDN |

组合使用 = [NekoPass Lite](https://github.com/Nyarime/NekoPass-Lite) 传输层。

## 许可证

Apache License 2.0

---

<a name="english"></a>
## English

TCP transport with fake-tls, WebSocket disguise, and PSK auth. TCP counterpart to [NRUP](https://github.com/Nyarime/NRUP).

```bash
go get github.com/nyarime/nrtp@v1.1.0
```

Modes: `none` / `tls` / `fake-tls` (fake-tls) / `ws` (WebSocket over TLS)

## CDN Fronting (Cloudflare)

```go
cfg := &nrtp.Config{
    Password: "secret",
    Mode:     "ws",
    WS: &nrtp.WSConfig{
        Path: "/ws",
        SNI:  "www.visa.com",  // CF背后的域名
        Headers: map[string]string{
            "Host":       "your-real-domain.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        },
    },
}
```

DPI 看到: TLS SNI=www.visa.com + 正常Chrome流量
