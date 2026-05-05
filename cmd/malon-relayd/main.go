package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/pabotesu/malon/config"
	"github.com/pabotesu/malon/internal/relay"
)

func main() {
	cfgPath := flag.String("config", "malon-relayd.toml", "path to config file")
	flag.Parse()

	cfg, err := config.LoadRelayServer(*cfgPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	r := relay.New()
	if err := r.ListenAndServe(cfg.Relay.ListenAddr, cfg.Relay.TLSCert, cfg.Relay.TLSKey); err != nil {
		slog.Error("relay exited", "err", err)
		os.Exit(1)
	}
}
