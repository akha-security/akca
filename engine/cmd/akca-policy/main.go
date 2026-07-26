package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/akha-security/akca/engine/internal/policy"
	"github.com/akha-security/akca/engine/internal/storage"
)

func main() {
	var current, previous, configPath, failOn string
	fs := flag.NewFlagSet("akca-policy", flag.ExitOnError)
	fs.StringVar(&current, "current", "", "current scan id")
	fs.StringVar(&previous, "previous", "", "optional baseline scan id")
	fs.StringVar(&configPath, "config", "", "optional policy JSON file")
	fs.StringVar(&failOn, "fail-on-new", "", "comma-separated severity override")
	_ = fs.Parse(os.Args[1:])
	if strings.TrimSpace(current) == "" || fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: akca-policy --current <scan-id> [--previous <scan-id>] [--config policy.json]")
		os.Exit(2)
	}
	cfg := policy.DefaultConfig()
	if configPath != "" {
		raw, err := os.ReadFile(configPath)
		if err != nil {
			exitError(err)
		}
		decoderConfig := policy.DefaultConfig()
		if err := json.Unmarshal(raw, &decoderConfig); err != nil {
			exitError(fmt.Errorf("invalid policy config: %w", err))
		}
		cfg = decoderConfig
	}
	if failOn != "" {
		cfg.FailOnNewSeverities = nil
		for _, severity := range strings.Split(failOn, ",") {
			if value := strings.ToLower(strings.TrimSpace(severity)); value != "" {
				cfg.FailOnNewSeverities = append(cfg.FailOnNewSeverities, value)
			}
		}
	}
	path, err := storage.DefaultDBPath()
	if err != nil {
		exitError(err)
	}
	db, err := storage.Open(path)
	if err != nil {
		exitError(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		exitError(err)
	}
	evaluation, err := policy.Evaluate(db, current, previous, cfg)
	if err != nil {
		exitError(err)
	}
	raw, _ := json.MarshalIndent(evaluation, "", "  ")
	fmt.Println(string(raw))
	if !evaluation.Passed {
		os.Exit(3)
	}
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, "akca-policy:", err)
	os.Exit(1)
}
