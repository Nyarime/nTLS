# NRTP

TCP 传输库，证书镜像 + PSK 认证。[NRUP](https://github.com/Nyarime/NRUP) 的 TCP 对应。

[English](#english)

## NRUP + NRTP

| | NRUP | NRTP |
|---|---|---|
| 传输层 | UDP | TCP |
| 加密 | nDTLS (AES-GCM/ChaCha20) | TLS 1.2+ |
| 伪装 | AnyConnect DTLS / QUIC | fake-tls 证书镜像 |
| 丢包恢复 | FEC + ARQ | TCP 重传 |
| 适用 | 实时/游戏/弱网 | 网页/下载/大文件 |

组合使用 = [NekoPass](https://github.com/Nyarime/NekoPass-Lite) 完整传输层。

## 使用

```go
import "github.com/nyarime/nrtp"

// 服务端
cfg := &nrtp.Config{
    Password: "secret",
    SNI:      "vpn2fa.hku.hk",  // 自动镜像证书
}
listener, _ := nrtp.Listen(":443", cfg)
conn, _ := listener.Accept()

// 客户端
conn, _ := nrtp.Dial("server:443", cfg)
conn.Write([]byte("hello"))
```

## 证书模式

| 模式 | 配置 | 说明 |
|------|------|------|
| fake-tls | `SNI: "vpn2fa.hku.hk"` | 从目标镜像证书 |
| 自定义 | `CertFile + KeyFile` | 自己的证书 |
| 自签名 | (默认) | 自动生成 |

## 许可证

Apache License 2.0

---

<a name="english"></a>
## English

TCP transport library with certificate mirroring + PSK auth. TCP counterpart to [NRUP](https://github.com/Nyarime/NRUP).

```go
// Server (mirrors cert from real VPN server)
cfg := &nrtp.Config{Password: "secret", SNI: "vpn2fa.hku.hk"}
listener, _ := nrtp.Listen(":443", cfg)
conn, _ := listener.Accept()

// Client
conn, _ := nrtp.Dial("server:443", cfg)
```
