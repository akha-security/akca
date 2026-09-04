package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/akha-security/akca/engine/internal/app"
	"github.com/akha-security/akca/engine/internal/branding"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/scanapi"
)

func main() {
	token := os.Getenv("AKCA_API_TOKEN")
	address := strings.TrimSpace(os.Getenv("AKCA_API_ADDR"))
	if address == "" {
		address = "127.0.0.1:19092"
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		exitf("invalid AKCA_API_ADDR: %v", err)
	}
	if net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		if !strings.EqualFold(os.Getenv("AKCA_API_ALLOW_REMOTE"), "true") {
			exitf("remote bind refused; use loopback or explicitly set AKCA_API_ALLOW_REMOTE=true behind TLS")
		}
	}
	engine, err := app.New(events.NewNDJSONWriter(io.Discard))
	if err != nil {
		exitf("engine initialization failed: %v", err)
	}
	defer engine.Close()
	api, err := scanapi.New(engine, token)
	if err != nil {
		exitf("%v", err)
	}
	server := &http.Server{
		Addr: address, Handler: api.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second,
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	fmt.Fprintf(os.Stderr, "%s JSON API listening on http://%s\n", branding.ProductName, address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		exitf("API server failed: %v", err)
	}
}

func exitf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, "akca-api: "+format+"\n", values...)
	os.Exit(1)
}
