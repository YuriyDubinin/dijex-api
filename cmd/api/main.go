package main

import (
	"fmt"
	"os"

	"github.com/YuriyDubinin/digix-api/internal/config"
	"github.com/YuriyDubinin/digix-api/pkg/logger"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	log := logger.New(cfg.Log.Level, cfg.App.Env)
	log.Info("service starting",
		"env", cfg.App.Env,
		"http_port", cfg.HTTP.Port,
	)

	log.Info("service stopped")
}
