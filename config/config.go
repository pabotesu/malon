package config

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config は malond 設定ファイル（WireGuard スタイル）全体を表す。
//
// Proxy 側の例:
//
//	[Interface]
//	PrivateKey   = <base64>
//	Address      = 100.100.0.3/24
//	ListenPort   = http3://:443, http2://:4443
//	Role         = proxy
//
//	[Peer]
//	PublicKey    = <base64>
//	AllowedIPs   = 100.100.0.1/32
//
// Client 側の例:
//
//	[Interface]
//	PrivateKey   = <base64>
//	Address      = 100.100.0.1/24
//	Role         = client
//
//	[Peer]
//	PublicKey    = <base64>
//	Relay        = https://relay.example.com:443
//	AllowedIPs   = 100.100.0.3/32, 100.100.0.2/32
type Config struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
}

// InterfaceConfig は [Interface] セクションを表す。
type InterfaceConfig struct {
	PrivateKey         string       // base64 encoded Ed25519 private key (seed or full)
	Address            netip.Prefix // TUN アドレス (e.g. 100.100.0.1/24)
	Role               string       // "client" or "proxy" (default: "client")
	ListenPort         string       // proxy mode: "http3://:443" or "http3://:443, http2://:4443"
	Relay              string       // relay URL this node connects to (required for proxy role)
	InsecureSkipVerify bool         // skip relay TLS cert verification (testing only)
}

// PeerConfig は [Peer] セクションを表す。
type PeerConfig struct {
	PublicKey  string         // base64 encoded Ed25519 public key
	Relay      string         // client mode: relay URL for this peer (e.g. https://relay.example.com:443)
	AllowedIPs []netip.Prefix // この peer 向けのアドレス範囲
}

// Parse はファイルパスから Config を読み込む。
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &Config{}
	scanner := bufio.NewScanner(f)
	section := ""
	var currentPeer *PeerConfig

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// コメント・空行をスキップ
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// セクションヘッダ
		if line == "[Interface]" {
			section = "interface"
			currentPeer = nil
			continue
		}
		if line == "[Peer]" {
			section = "peer"
			cfg.Peers = append(cfg.Peers, PeerConfig{})
			currentPeer = &cfg.Peers[len(cfg.Peers)-1]
			continue
		}
		// key = value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("config: invalid line: %s", line)
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// コメント除去（# 以降）
		if idx := strings.Index(val, " #"); idx >= 0 {
			val = strings.TrimSpace(val[:idx])
		}

		switch section {
		case "interface":
			if err := parseInterfaceField(&cfg.Interface, key, val); err != nil {
				return nil, err
			}
		case "peer":
			if currentPeer == nil {
				return nil, fmt.Errorf("config: key %s outside [Peer] section", key)
			}
			if err := parsePeerField(currentPeer, key, val); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("config: key %q outside any section", key)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseInterfaceField(iface *InterfaceConfig, key, val string) error {
	switch key {
	case "PrivateKey":
		iface.PrivateKey = val
	case "Address":
		prefix, err := netip.ParsePrefix(val)
		if err != nil {
			return fmt.Errorf("config: invalid Address %q: %w", val, err)
		}
		iface.Address = prefix
	case "Role":
		lower := strings.ToLower(val)
		if lower != "client" && lower != "proxy" {
			return fmt.Errorf("config: invalid Role %q (must be client or proxy)", val)
		}
		iface.Role = lower
	case "ListenPort":
		iface.ListenPort = val // proxy mode; parsed in main.go with parseMionListenEndpoints
	case "Relay":
		iface.Relay = val
	case "InsecureSkipVerify":
		iface.InsecureSkipVerify = strings.ToLower(val) == "true"
	default:
		return fmt.Errorf("config: unknown Interface key %q", key)
	}
	return nil
}

func parsePeerField(p *PeerConfig, key, val string) error {
	switch key {
	case "PublicKey":
		p.PublicKey = val
	case "Relay":
		p.Relay = val
	case "AllowedIPs":
		for _, s := range strings.Split(val, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return fmt.Errorf("config: invalid AllowedIPs %q: %w", s, err)
			}
			p.AllowedIPs = append(p.AllowedIPs, prefix)
		}
	default:
		return fmt.Errorf("config: unknown Peer key %q", key)
	}
	return nil
}

// ── relayd 用（TOML のまま）──────────────────────────────────────────────────

// RelayServerConfig は malon-relayd.toml 全体を表す。
type RelayServerConfig struct {
	Relay RelayServerSection `toml:"relay"`
}

type RelayServerSection struct {
	ListenAddr string `toml:"listen_addr"`
	TLSCert    string `toml:"tls_cert"`
	TLSKey     string `toml:"tls_key"`
}

// LoadRelayServer は malon-relayd.toml を読み込む。
func LoadRelayServer(path string) (*RelayServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg RelayServerConfig
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// duration は toml の文字列("5s" など)を time.Duration として扱うための型。
type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))

	return err
}
