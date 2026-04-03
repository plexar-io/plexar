package web

import (
	"embed"
	"io/fs"
)

//go:embed dashboard/*
var dashboardContent embed.FS

// DashboardFS returns the embedded filesystem for the enterprise dashboard
func DashboardFS() (fs.FS, error) {
	return fs.Sub(dashboardContent, "dashboard")
}
