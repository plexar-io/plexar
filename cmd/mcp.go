package cmd

import (
	"fmt"
	"os"

	"github.com/plexar-security/plexar/pkg/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "◈ Run Plexar as an MCP (Model Context Protocol) server",
	Long: `◈ Starts Plexar as an MCP server over stdio for AI assistant integration.

Exposes tools: scan_namespace, get_pod_risk, check_compliance,
classify_workloads, find_critical_cves, audit_rbac.

Usage with Claude Desktop, Cursor, or other MCP clients:
  Add to your MCP config:
    {
      "mcpServers": {
        "plexar": {
          "command": "plexar",
          "args": ["mcp", "--namespace", "production"]
        }
      }
    }`,
	RunE: runMCP,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}

func runMCP(cmd *cobra.Command, args []string) error {
	fmt.Fprintf(os.Stderr, "🛡  Plexar MCP server starting (namespace: %s)\n", namespace)
	server := mcp.NewServer(kubeconfig)
	return server.Run()
}
