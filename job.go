package main

import (
	"context"
	"sync"
)

// ====================
// Job Management (for scanning and polling)
// ====================

// ScanJob holds the state of an ongoing scan.
type ScanJob struct {
	JobID      string         `json:"job_id"`
	Query      string         `json:"query"`
	ScanUUID   string         `json:"scan_uuid"` // the UUID returned by the API
	Result     *URLScanResult `json:"result,omitempty"`
	Error      string         `json:"error,omitempty"`
	Status     string         `json:"status"` // pending, ready, warning, error, cancelled
	cancelFunc context.CancelFunc
}

var (
	jobStore   = make(map[string]*ScanJob)
	jobStoreMu sync.RWMutex
)

func saveJob(job *ScanJob) {
	jobStoreMu.Lock()
	defer jobStoreMu.Unlock()
	jobStore[job.JobID] = job
}

func getJob(jobID string) (*ScanJob, bool) {
	jobStoreMu.RLock()
	defer jobStoreMu.RUnlock()
	job, ok := jobStore[jobID]
	return job, ok
}

func removeJob(jobID string) {
	jobStoreMu.Lock()
	defer jobStoreMu.Unlock()
	delete(jobStore, jobID)
}
