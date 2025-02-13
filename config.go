package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ====================
// Configuration
// ====================

// Config holds all configurable parameters.
type Config struct {
	SOCKS5Proxy       string `yaml:"socks5_proxy"`       // e.g., "127.0.0.1:9050" (required)
	APIKey            string `yaml:"api_key"`            // your urlscan.io API key (required)
	PollingInterval   int    `yaml:"polling_interval"`   // in seconds, default 10
	InitialTimeout    int    `yaml:"initial_timeout"`    // in seconds, default 300 (5 minutes)
	AdditionalTimeout int    `yaml:"additional_timeout"` // in seconds, default 300 (5 minutes)
}

// defaultConfig returns default configuration values.
func defaultConfig() *Config {
	return &Config{
		SOCKS5Proxy:       "127.0.0.1:9050",
		APIKey:            "",
		PollingInterval:   10,
		InitialTimeout:    300,
		AdditionalTimeout: 300,
	}
}

// configFile returns the full path to the configuration file.
func configFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".urlscan_client.yaml"), nil
}

// promptForConfig interactively prompts the user for required configuration values.
func promptForConfig(defaults *Config) *Config {
	reader := bufio.NewReader(os.Stdin)
	cfg := *defaults // copy defaults

	// Prompt for SOCKS5 proxy
	for {
		fmt.Printf("Enter SOCKS5 proxy address (host:port) [%s]: ", cfg.SOCKS5Proxy)
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text != "" {
			cfg.SOCKS5Proxy = text
		}
		if cfg.SOCKS5Proxy != "" {
			break
		}
	}

	// Prompt for API key (can be empty, but warn the user)
	fmt.Printf("Enter urlscan.io API key (leave empty if not available): ")
	text, _ := reader.ReadString('\n')
	cfg.APIKey = strings.TrimSpace(text)

	// For DisplayFields we can just use defaults. In a more advanced version you could prompt too.
	return &cfg
}

// loadConfig loads the YAML configuration from file. If the file does not exist,
// it interactively prompts the user for the configuration and then saves it.
func loadConfig() (*Config, error) {
	cfgPath, err := configFile()
	if err != nil {
		return nil, err
	}

	cfg := defaultConfig()

	if _, err := os.Stat(cfgPath); err == nil {
		// Config file exists: load it.
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("reading config: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("unmarshaling config: %w", err)
		}
		// Check for required fields; if missing, prompt interactively.
		changed := false
		if strings.TrimSpace(cfg.SOCKS5Proxy) == "" {
			fmt.Println("SOCKS5 proxy is missing in config.")
			cfg.SOCKS5Proxy = defaultConfig().SOCKS5Proxy
			changed = true
		}
		// (API key can be empty.)
		if changed {
			// Save the updated config.
			out, err := yaml.Marshal(cfg)
			if err != nil {
				return nil, fmt.Errorf("marshaling updated config: %w", err)
			}
			if err := os.WriteFile(cfgPath, out, 0600); err != nil {
				return nil, fmt.Errorf("writing updated config: %w", err)
			}
		}
	} else {
		// Config file does not exist; prompt the user.
		fmt.Println("Configuration file not found; please provide the following details.")
		cfg = promptForConfig(cfg)
		// Save the config.
		out, err := yaml.Marshal(cfg)
		if err != nil {
			return nil, fmt.Errorf("marshaling config: %w", err)
		}
		if err := os.WriteFile(cfgPath, out, 0600); err != nil {
			return nil, fmt.Errorf("writing config: %w", err)
		}
		fmt.Printf("Configuration saved to %s\n", cfgPath)
	}

	// Make sure the required SOCKS5 proxy is set.
	if cfg.SOCKS5Proxy == "" {
		return nil, fmt.Errorf("SOCKS5 proxy must be defined in config")
	}
	return cfg, nil
}
