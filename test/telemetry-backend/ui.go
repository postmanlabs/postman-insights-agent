package main

import (
	_ "embed"

	"github.com/nxtcoder17/ivy"
)

//go:embed telemetry-dashboard.html
var telemetryDashboardHTML []byte

func telemetryDashboard(c *ivy.Context) error {
	return c.SendHTML(telemetryDashboardHTML)
}
