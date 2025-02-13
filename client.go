package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/toxyl/tor-url-scan/log"
	"golang.org/x/net/proxy"
)

// ====================
// URLScan API Client
// ====================

const defaultBaseURL = "https://urlscan.io/api/v1"

// ScanRequest is the payload for initiating a scan.
type ScanRequest struct {
	URL        string `json:"url"`
	Visibility string `json:"visibility,omitempty"` // "public", "private", or "unlisted"
}

// ScanResponse is the response from a scan initiation.
type ScanResponse struct {
	UUID    string `json:"uuid"`
	Message string `json:"message,omitempty"`
}

// SearchResult represents one entry in the search response.
type SearchResult struct {
	UUID   string `json:"uuid"`
	URL    string `json:"url"`
	Domain string `json:"domain"`
}

// SearchResponse represents the response from a search query.
type SearchResponse struct {
	Total   int            `json:"total"`
	Results []SearchResult `json:"results"`
}

// URLScanClient represents a client for the URLScan API.
type URLScanClient struct {
	APIKey     string
	BaseURL    string
	HTTPClient *http.Client
}

// NewURLScanClient creates a new URLScanClient using the given config and sets up the SOCKS5 proxy.
func NewURLScanClient(cfg *Config) (*URLScanClient, error) {
	// Set up SOCKS5 dialer.
	dialer, err := proxy.SOCKS5("tcp", cfg.SOCKS5Proxy, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain SOCKS5 dialer: %w", err)
	}
	// Create our own Transport that uses the SOCKS5 dialer.
	transport := &http.Transport{
		Dial: dialer.Dial,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	return &URLScanClient{
		APIKey:     cfg.APIKey,
		BaseURL:    defaultBaseURL,
		HTTPClient: httpClient,
	}, nil
}

// ScanURL submits a scan request.
func (c *URLScanClient) ScanURL(reqData ScanRequest) (*ScanResponse, error) {
	endpoint := c.BaseURL + "/scan/"

	payload, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scan request: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Use the lowercase header as required.
	if c.APIKey != "" {
		req.Header.Set("api-key", c.APIKey)
	}

	log.Blank("POST %s", endpoint)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("non-success status code %d: %s", resp.StatusCode, string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	var scanResp ScanResponse
	if err := json.Unmarshal(body, &scanResp); err != nil {
		return nil, fmt.Errorf("failed to decode scan response: %w", err)
	}
	return &scanResp, nil
}

// GetResult retrieves a scan result by UUID.
func (c *URLScanClient) GetResult(uuid string) (*URLScanResult, error) {
	if uuid == "" {
		return nil, fmt.Errorf("Can't get result for empty UUID!")
	}
	endpoint := fmt.Sprintf("%s/result/%s/", c.BaseURL, uuid)
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}
	if c.APIKey != "" {
		req.Header.Set("api-key", c.APIKey)
	}
	log.Blank("GET %s", endpoint)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("non-success status code %d: %s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	var result URLScanResult
	if err := json.Unmarshal(body, &result); err != nil {
		log.Error("failed to decode scan result: %v", err)
		return nil, fmt.Errorf("failed to decode scan result: %w", err)
	}
	return &result, nil
}

// Search executes a search query.
func (c *URLScanClient) Search(query string) (*SearchResponse, error) {
	qs := url.QueryEscape(query)
	endpoint := fmt.Sprintf("%s/search/?q=%s", c.BaseURL, qs)
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create search request: %w", err)
	}
	if c.APIKey != "" {
		req.Header.Set("api-key", c.APIKey)
	}
	log.Blank("GET %s", endpoint)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP search request failed: %w", err)
	}
	defer resp.Body.Close()
	body := []byte{}
	if resp.StatusCode != http.StatusOK {
		body, _ = io.ReadAll(resp.Body)
		return nil, fmt.Errorf("non-success status code %d: %s", resp.StatusCode, string(body))
	}
	var searchResp SearchResponse
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}
	return &searchResp, nil
}
