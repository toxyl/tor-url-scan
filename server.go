package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/google/uuid"
	"github.com/toxyl/flo"
	"github.com/toxyl/tor-url-scan/log"
)

//go:embed views/index.html
var index string

// ====================
// Fiber Server & Endpoints
// ====================

func startServer(cfg *Config, apiClient *URLScanClient) {
	dir := filepath.Join(filepath.Dir(os.Args[0]), "views")
	if !flo.File(dir + "/index.html").Exists() {
		if err := flo.File(dir + "/index.html").StoreString(index); err != nil {
			log.Fatal("Could not create default template: %s", err)
		}
	}
	engine := html.New(dir, ".html")
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// GET "/" renders the main search page.
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{})
	})

	// POST "/search" processes the search/scan request.
	app.Post("/search", func(c *fiber.Ctx) error {
		query := c.FormValue("query")
		scanType := c.FormValue("scanType")

		visibility := "private"
		switch scanType {
		case "public", "private", "unlisted":
			visibility = scanType
		default:
			return c.Status(fiber.StatusBadRequest).SendString("Illegal scan type.")
		}

		if query == "" {
			return c.Status(fiber.StatusBadRequest).SendString("Query cannot be empty.")
		}

		// Check our in-memory cache.
		if cached, found := cacheGet(query); found {
			return c.JSON(fiber.Map{
				"status": "ready",
				"result": cached,
			})
		}

		// Or try a search via the API.
		searchResp, err := apiClient.Search(query)
		if err == nil && searchResp.Total > 0 {
			// Pick the most recent result (assume the first result is most recent).
			resultID := searchResp.Results[0].UUID
			result, err := apiClient.GetResult(resultID)
			if err == nil {
				report := result
				cacheSet(query, report)
				return c.JSON(fiber.Map{
					"status": "ready",
					"result": report.GenerateReport(),
				})
			}
		}

		// Initiate scan via API.
		scanResp, err := apiClient.ScanURL(ScanRequest{
			URL:        query,
			Visibility: visibility,
		})
		if err != nil {
			log.Error("Error initiating scan: %v", err)
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to initiate scan.")
		}
		log.Blank("Scan initiated: %s", scanResp.UUID)

		// Create a new scan job.
		jobID := uuid.New().String()
		job := &ScanJob{
			JobID:    jobID,
			Query:    query,
			ScanUUID: scanResp.UUID,
			Status:   "pending",
		}
		saveJob(job)

		// Start the polling routine as a background goroutine.
		go pollForResult(apiClient, job, cfg)

		// Return the job ID to the frontend.
		return c.JSON(fiber.Map{
			"status": "pending",
			"job_id": jobID,
		})
	})

	// GET "/status" returns the current status of a scan job.
	app.Get("/status", func(c *fiber.Ctx) error {
		jobID := c.Query("job_id")
		if jobID == "" {
			return c.Status(fiber.StatusBadRequest).SendString("Missing job_id")
		}
		job, ok := getJob(jobID)
		if !ok {
			return c.Status(fiber.StatusNotFound).SendString("Job not found")
		}
		return c.JSON(job)
	})

	// Start Fiber on local port.
	log.Fatal("server crashed: %s", app.Listen(":"+fmt.Sprint(cfg.LocalPort)))
}
