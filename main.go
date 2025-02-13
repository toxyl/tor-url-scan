package main

import "github.com/toxyl/tor-url-scan/log"

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal("Error loading config: %v", err)
	}

	apiClient, err := NewURLScanClient(cfg)
	if err != nil {
		log.Fatal("Error creating URLScan API client: %v", err)
	}

	startServer(cfg, apiClient)
}
