package main

import (
	"sync"
	"time"

	"github.com/toxyl/tor-url-scan/log"
)

// ====================
// In‑Memory Cache
// ====================

type cacheItem struct {
	result     *URLScanResult
	expiration time.Time
}

var (
	cacheMu     sync.RWMutex
	resultCache = make(map[string]cacheItem)
	cacheTTL    = time.Hour // 1‑hour expiration
)

// cacheGet retrieves a cached URLScanResult if present and not expired.
func cacheGet(key string) (*URLScanResult, bool) {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	item, exists := resultCache[key]
	if !exists || time.Now().After(item.expiration) {
		return nil, false
	}
	log.Blank("Cache hit for key %s", key)
	return item.result, true
}

// cacheSet stores a URLScanResult in the cache with a TTL.
func cacheSet(key string, result *URLScanResult) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	resultCache[key] = cacheItem{
		result:     result,
		expiration: time.Now().Add(cacheTTL),
	}
}
