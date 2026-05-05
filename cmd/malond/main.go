package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/pabotesu/malon/config"
	"github.com/pabotesu/malon/internal/manager"
	mionpkg "github.com/pabotesu/mion/mion"
	"github.com/pabotesu/mion/peer"
)

func main() {
	cfgPath := "malond.toml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("failed to load config", "path", cfgPath, "err", err)
		os.Exit(1)
	}

	// Decode self private key (base64-encoded Ed25519 seed or full key).
	privRaw, err := base64.StdEncoding.DecodeString(cfg.Self.PrivateKey)
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

	// Build mion.Config (client role — MALON drives the relay connection).
	mionCfg := mionpkg.Config{
		InterfaceName: "mion0",
		PrivateKey:    selfPriv,
		Role:          mionpkg.RoleClient,
	}
	if cfg.Self.ListenAddr != "" {
		// Parse the TUN address if specified in config (e.g. "10.0.0.1/24").
		prefix, err := netip.ParsePrefix(cfg.Self.ListenAddr)
		if err == nil {
			mionCfg.Address = prefix
		}
	}

	mionInst, err := mionpkg.New(mionCfg)
	if err != nil {
		slog.Error("failed to create mion instance", "err", err)
		os.Exit(1)
	}

	// Create Manager.
	mgr := manager.New(selfPriv, cfg.Relay.Endpoint, cfg.Relay.InsecureSkipVerify, mionInst)

	// Register peers into both mion and manager.
	for _, pc := range cfg.Peers {
		pubRaw, err := base64.StdEncoding.DecodeString(pc.PublicKey)
		if err != nil {
			slog.Error("failed to decode peer public key", "err", err)
			os.Exit(1)
		}
		pub := ed25519.PublicKey(pubRaw)

		var allowedIPs []netip.Prefix
		for _, s := range pc.AllowedIPs {
			prefix, err := netip.ParsePrefix(s)
			if err != nil {
				slog.Error("invalid allowed_ip", "cidr", s, "err", err)
				os.Exit(1)
			}
			allowedIPs = append(allowedIPs, prefix)
		}

		p := &peer.Peer{
			PublicKey:  pub,
			AllowedIPs: allowedIPs,
		}
		if err := mionInst.AddPeer(p); err != nil {
			slog.Error("failed to add peer to mion", "err", err)
			os.Exit(1)
		}
		if err := mgr.RegisterPeer(pub, p); err != nil {
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

	// mion の client 初期化（m.client = c）が完了してから Manager を起動する。
	// これにより StartForwardConnToTUN が m.client == nil で空振りするのを防ぐ。
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
