package main

import (
	"context"
	"time"
)

// pollForResult polls the URLScan API until the scan result is ready or timeouts occur.
// It uses an initial timeout (e.g., 5 minutes) then enters a warning state and allows an additional period.
// The job is updated with time remaining and status. The user can also cancel the job.
func pollForResult(apiClient *URLScanClient, job *ScanJob, cfg *Config) {
	initialTimeout := time.Duration(cfg.InitialTimeout) * time.Second
	additionalTimeout := time.Duration(cfg.AdditionalTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), initialTimeout)
	job.cancelFunc = cancel

	ticker := time.NewTicker(time.Duration(cfg.PollingInterval) * time.Second)
	defer ticker.Stop()

	var result *URLScanResult
	var pollErr error

loop:
	for {
		select {
		case <-ctx.Done():
			// Initial timeout reached.
			job.Status = "warning"
			// Extend for the additional timeout.
			ctx2, cancel2 := context.WithTimeout(context.Background(), additionalTimeout)
			job.cancelFunc = cancel2
			for {
				select {
				case <-ticker.C:
					result, pollErr = apiClient.GetResult(job.ScanUUID)
					if pollErr == nil && result != nil {
						job.Status = "ready"
						job.Result = result
						cacheSet(job.Query, job.Result)
						break loop
					}
				case <-ctx2.Done():
					job.Status = "error"
					job.Error = "Scan result not available after extended timeout."
					break loop
				}
			}
		case <-ticker.C:
			result, pollErr = apiClient.GetResult(job.ScanUUID)
			if pollErr == nil && result != nil {
				job.Status = "ready"
				job.Result = result
				cacheSet(job.Query, job.Result)
				break loop
			}
		}
	}

	// Remove the job from our store after one hour.
	time.AfterFunc(time.Hour, func() {
		removeJob(job.JobID)
	})
}
