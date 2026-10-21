package main

import (
	"flag"
	"github.com/nxtcoder17/fastlog"
	"github.com/nxtcoder17/ivy"
	ivyLogger "github.com/nxtcoder17/ivy/middleware/logger"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	addr := flag.String("addr", ":1717", "--addr [:]<port>")
	dbPath := flag.String("db", "telemetry.db", "SQLite database path")
	debug := flag.Bool("debug", false, "--debug")
	flag.Parse()

	logger := fastlog.New().DebugMode(*debug).Colors(true).Console()
	fastlog.SetDefaultLogger(logger)
	slog.SetDefault(logger.Slog())

	store, err := openStore(*dbPath)
	if err != nil {
		logger.Error("Failed to open SQLite database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	router := newRouter(store)

	logger.Info("Starting HTTP Server", "addr", *addr)
	if err := http.ListenAndServe(*addr, router); err != nil {
		panic(err)
	}
}

func newRouter(store *store) *ivy.Router {
	router := ivy.NewRouter()
	router.Use(ivyLogger.New())
	router.Get("/healthz", func(c *ivy.Context) error {
		return c.JSON(map[string]any{"message": "OK"})
	})
	router.Get("/ui", telemetryDashboard)
	router.Post("/v2/agent/daemonset/telemetry", store.handleTelemetry)
	router.Get("/inspect/telemetry", store.inspectTelemetry)
	router.Get("/api/summary", store.apiSummary)
	router.Get("/api/agents", store.apiAgents)
	router.Get("/api/targets", store.apiTargets)
	router.Get("/api/drop-reasons", store.apiDropReasons)
	router.Get("/api/drop-reasons/by-cluster", store.apiDropReasonsByCluster)
	router.Get("/api/failure-breakdown", store.apiFailureBreakdown)
	router.Get("/api/agent-lifecycle", store.apiAgentLifecycle)
	router.Get("/api/version-adoption", store.apiVersionAdoption)
	router.Get("/api/cluster-inventory", store.apiClusterInventory)
	router.Get("/api/sequence-gaps", store.apiSequenceGaps)
	router.Get("/api/window-gaps", store.apiWindowGaps)
	return router
}
