package main

import (
	"github.com/toshokan/frontier/internal/config"
	"github.com/toshokan/frontier/internal/server"
)

func main() {
	cfg := config.LoadEnv();
	server.Mount(&cfg)
}
