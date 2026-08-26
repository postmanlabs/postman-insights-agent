package main

import (
	"flag"
	"github.com/nxtcoder17/fastlog"
	"github.com/nxtcoder17/ivy"
	ivyLogger "github.com/nxtcoder17/ivy/middleware/logger"
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

	store, err := openStore(*dbPath)
	if err != nil {
		logger.Error("Failed to open SQLite database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	router := ivy.NewRouter()
	router.Use(ivyLogger.New())
	router.Get("/healthz", func(c *ivy.Context) error {
		return c.JSON(map[string]any{"message": "OK"})
	})
	router.Post("/v2/agent/daemonset/telemetry", store.handleTelemetry)
	router.Get("/inspect/telemetry", store.inspectTelemetry)

	logger.Info("Starting HTTP Server", "addr", *addr)
	if err := http.ListenAndServe(*addr, router); err != nil {
		panic(err)
	}
}
