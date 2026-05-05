package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/pabotesu/malon/config"
	"github.com/pabotesu/malon/internal/manager"
	mionconfig "github.com/pabotesu/mion/config"
	mionpkg "github.com/pabotesu/mion/mion"
	"github.com/pabotesu/mion/peer"
)

func main() {
	cfgPath := "malond.conf"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("failed to load config", "path", cfgPath, "err", err)
		os.Exit(1)
	}

	// Decode self private key (base64-encoded Ed25519 seed or full key).
	privRaw, err := base64.StdEncoding.DecodeString(cfg.Interface.PrivateKey)
	if err != nil {
		slog.Error("failed to decode self private key", "err", err)
		os.Exit(1)
	}
	var selfPriv ed25519.PrivateKey
	switch len(privRaw) {
	case ed25519.SeedSize:
		selfPriv = ed25519.NewKeyFromSeed(privRaw)
	case ed25519.PrivateKeySize:
		selfPriv = ed25519.PrivateKey(privRaw)
	default:
		slog.Error("self private key has wrong length", "len", len(privRaw))
		os.Exit(1)
	}

	// Build mion.Config.
	mionRole := mionpkg.RoleClient
	if cfg.Interface.Role == "proxy" {
		mionRole = mionpkg.RoleProxy
	}

	// ListenPort: "http3://:443, http2://:4443" → []mionconfig.ListenEndpoint
	listenEndpoints, err := parseMionListenEndpoints(cfg.Interface.ListenPort)
	if err != nil {
		slog.Error("invalid ListenPort", "err", err)
		os.Exit(1)
	}

	mionCfg := mionpkg.Config{
		InterfaceName:   "mion0",
		PrivateKey:      selfPriv,
		Role:            mionRole,
		Address:         cfg.Interface.Address,
		ListenEndpoints: listenEndpoints,
	}

	mionInst, err := mionpkg.New(mionCfg)
	if err != nil {
		slog.Error("failed to create mion instance", "err", err)
		os.Exit(1)
	}

	// Create Manager (no global relay URL; each peer carries its own).
	mgr := manager.New(selfPriv, cfg.Interface.InsecureSkipVerify, mionInst)

	// Register peers into both mion and manager.
	for _, pc := range cfg.Peers {
		pubRaw, err := base64.StdEncoding.DecodeString(pc.PublicKey)
		if err != nil {
			slog.Error("failed to decode peer public key", "err", err)
			os.Exit(1)
		}
		pub := ed25519.PublicKey(pubRaw)

		p := &peer.Peer{
			PublicKey:  pub,
			AllowedIPs: pc.AllowedIPs,
		}
		if err := mionInst.AddPeer(p); err != nil {
			slog.Error("failed to add peer to mion", "err", err)
			os.Exit(1)
		}
		if err := mgr.RegisterPeer(pub, p, pc.Relay); err != nil {
			slog.Error("failed to register peer with manager", "err", err)
			os.Exit(1)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)

	go func() {
		if err := mionInst.Run(ctx); err != nil {
			errCh <- err
		}
	}()

	// mion の client 初期化完了を待ってから Manager を起動する。
	select {
	case <-mionInst.ClientReady():
		slog.Info("malond: mion client ready, starting manager")
	case <-ctx.Done():
		return
	case err := <-errCh:
		slog.Error("malond: mion startup failed", "err", err)
		os.Exit(1)
	}

	go func() {
		if err := mgr.Run(ctx); err != nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("malond: shutting down")
	case err := <-errCh:
		slog.Error("malond: fatal error", "err", err)
		os.Exit(1)
	}
}

// parseMionListenEndpoints parses a comma-separated string like
// "http3://:443, http2://:4443" into []mionconfig.ListenEndpoint.
// This mirrors mion's internal parseListenEndpoints (which is unexported).
func parseMionListenEndpoints(raw string) ([]mionconfig.ListenEndpoint, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var ends []mionconfig.ListenEndpoint
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		u, err := url.Parse(entry)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("invalid ListenPort entry %q: use http3://:port or http2://:port", entry)
		}
		proto := strings.ToLower(u.Scheme)
		if proto != "http2" && proto != "http3" {
			return nil, fmt.Errorf("unknown protocol %q in ListenPort %q (use http2:// or http3://)", proto, entry)
		}
		host, portStr, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, fmt.Errorf("invalid address in ListenPort %q: %w", entry, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port in ListenPort %q", entry)
		}
		ends = append(ends, mionconfig.ListenEndpoint{Protocol: proto, Host: host, Port: port})
	}
	return ends, nil
}
