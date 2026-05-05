package config

import (
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config は malond.toml 全体を表す。
type Config struct {
	Self      SelfConfig      `toml:"self"`
	Relay     RelayConfig     `toml:"relay"`
	STUN      STUNConfig      `toml:"stun"`
	Peers     []PeerConfig    `toml:"peer"`
	Transport TransportConfig `toml:"transport"`
}

type SelfConfig struct {
	PrivateKey string `toml:"private_key"` // base64 encoded Ed25519 private key
	ListenAddr string `toml:"listen_addr"`
}

type RelayConfig struct {
	Endpoint string `toml:"endpoint"` // https://relay.example.com:443
}

type STUNConfig struct {
	Servers []string `toml:"servers"`
}

type PeerConfig struct {
	PublicKey  string   `toml:"public_key"` // base64 encoded Ed25519 public key
	AllowedIPs []string `toml:"allowed_ips"`
}

type TransportConfig struct {
	ValidationTimeout duration `toml:"validation_timeout"`
	RelayReconnectMax duration `toml:"relay_reconnect_max"`
	KeepaliveInterval duration `toml:"keepalive_interval"`
}

// RelayServerConfig は malon-relayd.toml 全体を表す。
type RelayServerConfig struct {
	Relay RelayServerSection `toml:"relay"`
}

type RelayServerSection struct {
	ListenAddr string `toml:"listen_addr"`
	TLSCert    string `toml:"tls_cert"`
	TLSKey     string `toml:"tls_key"`
}

// Load は toml ファイルを読み込んで Config を返す。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
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
