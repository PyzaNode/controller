package main

import (
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pyzanode/controller/internal/api"
	"github.com/pyzanode/controller/internal/auth"
	"github.com/pyzanode/controller/internal/hub"
	"github.com/pyzanode/controller/internal/store"
	"github.com/pyzanode/shared/config"
	"github.com/pyzanode/shared/debuglog"
)

func main() {
	webDir := flag.String("web", "", "path to built dashboard (e.g. web/dist) to use instead of embedded; default uses embedded build at /dashboard/")
	flag.Parse()

	cfg := config.DefaultControllerConfig()
	if *webDir != "" {
		cfg.WebDir = *webDir
	}
	dataDir := cfg.DataDir
	secretsPath := filepath.Join(dataDir, cfg.SecretsFile)

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("mkdir data dir: %v", err)
	}

	authSvc, err := auth.New(secretsPath)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	token, err := authSvc.EnsureSecrets()
	if err != nil {
		log.Fatalf("ensure secrets: %v", err)
	}

	st, err := store.New(dataDir)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	debuglog.Enabled = st.GetSettings().DebugLogging

	h := hub.New()
	apiSvc := api.New(st, authSvc)
	var embedWeb *fs.FS
	if root, err := webUIRoot(); err == nil {
		embedWeb = &root
	}
	handler := apiSvc.Router(cfg.WebSocketPath, h, cfg.WebDir, embedWeb)

	log.Printf("PyzaNode controller at http://%s", cfg.HTTPAddr)
	if cfg.WebDir != "" {
		log.Printf("Dashboard at /dashboard/ (from %s)", cfg.WebDir)
	} else if embedWeb != nil {
		log.Printf("Dashboard at /dashboard/ (embedded)")
	}
	log.Printf("Data dir: %s", dataDir)
	log.Printf("Agent token: %s", token)
	log.Printf("Connect agent: pyzanode-agent connect http://<this-ip>:9451 %s", token)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
