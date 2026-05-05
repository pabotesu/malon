# malon

**malon** は [mion](https://github.com/pabotesu/mion) の通信経路を管理する接続ランタイムです。  
Relay（H2 over TLS）を常時フォールバックとして維持しながら、CGNAT 越えの NAT hole punching による P2P（QUIC/H3）直接経路を自動確立・切替します。

---

## アーキテクチャ

```
[client node]                        [proxy node]
  mion TUN                             mion TUN
     ↕ raw IP packet                      ↕ raw IP packet
  Manager                              Manager
  ├─ relay path ──────────────────── relay path
  │    └─ h2proxy (HTTP/2 CONNECT)        └─ h2proxy (HTTP/2 CONNECT)
  │         └──── malon-relayd ───────────┘
  └─ direct path (QUIC/H3)           └─ direct path (QUIC/H3)
       └─ NAT hole punching ──────────────┘
```

### コンポーネント

| パッケージ | 役割 |
|---|---|
| `internal/manager` | 全経路の統合管理。relay/P2P の切替、candidates 交換、path promotion |
| `internal/h2proxy` | HTTP/2 CONNECT over TLS による relay トンネル。envelope + inner mTLS |
| `internal/relay` | malon-relayd サーバー本体（HTTP/2 CONNECT を中継） |
| `internal/direct` | DirectListener（QUIC UDP ソケット共有）と CONNECT-IP dial |
| `internal/h3path` | P2P 候補の QUIC probe・検証（`ValidatedTransport`） |
| `internal/stun` | DirectListener の UDP ソケットを共有する STUN クエリ |
| `internal/candidate` | `embedded`（ローカル IP）と `stuned`（STUN 取得外部 IP）候補 |
| `internal/control` | candidates をカプセルで交換する制御メッセージ |
| `internal/auth` | Ed25519 鍵を使った相互 TLS（inner mTLS）設定 |
| `internal/envelope` | relay セッションの多重化フレーム |

---

## 経路切替の仕組み

### 1. 起動〜relay 確立

1. **client** が relay に HTTP/2 CONNECT でトンネルを張る
2. client → relay → proxy の 2-hop で inner mTLS ハンドシェイク（`connectPeerWithCtx`）
3. relay 経由でデータ転送開始

### 2. P2P hole punching

1. 両端が `embedded`（ローカル IP:port）と `stuned`（STUN で取得した外部 IP:port）candidates を control カプセルで交換
2. DirectListener の **同一 UDP ソケット**から相手の candidates に QUIC probe を送出（NAT エントリを双方向に開ける）
3. probe 成功 → `ValidatedTransport` を取得 → client が CONNECT-IP dial で P2P セッションを確立
4. `peer.SetConn` で mion の active path を relay から P2P に切替（path promotion）

### 3. P2P 切断 → relay フォールバック

- `forwardDirectConnToTUN` が EOF/timeout を検出 → `fallbackToRelay`
- **proxy**: 既存の relay conn が生きていれば即 `peer.SetConn(relayConn)` で切り戻し
- **client**: `retryConnectPeer` が relay 再接続まで backoff リトライ

### 4. relay flap 中も P2P 維持

- `setupRelayPeers` は `hasDirectPath` をリセットしない
- relay が一時的に切れても QUIC P2P セッションは独立して生存
- relay 復旧後、client のみが `retryConnectPeer` を起動（proxy は `handleIncoming` で待機）

---

## role の違い

| | client | proxy |
|---|---|---|
| relay 接続 | 自発的に outbound dial | `handleIncoming` で client からの接続を受け入れ |
| P2P 確立 | probe 後に CONNECT-IP dial | probe だけ送り、inbound CONNECT-IP を `handleDirectConnect` で受け入れ |
| P2P 切断後 | `retryConnectPeer` で relay 再接続 | 既存 relay conn で即切り戻し。なければ client の再接続を待つ |

---

## セキュリティ

- 全ての peer 間通信は **inner mTLS**（Ed25519 自己署名証明書）で保護
- relay はデータを復号しない。envelope フレームを中継するだけ
- peer の認証は `auth.NewClientTLSConfig` / `auth.NewServerTLSConfig` が公開鍵リストで検証

---

## バイナリ

| バイナリ | 説明 |
|---|---|
| `malond` | client / proxy 統合デーモン |
| `malon-relayd` | relay サーバー |

---

## 設定ファイル（TOML / WireGuard スタイル）

### client 側 (`/etc/malon/malond.conf`)

```toml
[Interface]
PrivateKey = <base64 Ed25519 private key>
Address    = 100.100.100.1/24
Role       = client

[Peer]
PublicKey  = <base64 Ed25519 public key of proxy>
Relay      = https://relay.example.com:8443
AllowedIPs = 100.100.100.2/32
```

### proxy 側 (`/etc/malon/malond.conf`)

```toml
[Interface]
PrivateKey  = <base64 Ed25519 private key>
Address     = 100.100.100.2/24
Role        = proxy
ListenPort  = http3://:443, http2://:4443
Relay       = https://relay.example.com:8443

[Peer]
PublicKey  = <base64 Ed25519 public key of client>
AllowedIPs = 100.100.100.1/32
```

### relay サーバー (`malon-relayd.toml`)

```toml
[Relay]
ListenAddr = ":8443"
TLSCert    = "/etc/malon/cert.pem"
TLSKey     = "/etc/malon/key.pem"
```

---

## ビルド

```bash
# Nix (推奨)
nix develop
go build ./cmd/malond/
go build ./cmd/malon-relayd/

# 通常
go build ./cmd/malond/
go build ./cmd/malon-relayd/
```

---

## 依存

- [mion](https://github.com/pabotesu/mion) — TUN / CONNECT-IP コア
- [quic-go](https://github.com/quic-go/quic-go) v0.59.0
- [connect-ip-go](https://github.com/quic-go/connect-ip-go) v0.1.0
- [pion/stun](https://github.com/pion/stun) v3
