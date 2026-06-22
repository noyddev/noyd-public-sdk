// testserver/main.go — Local Test Server for NOYD SDK
// Starts a local NOYD PQC server for testing the SDK without external dependencies.

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/noyddev/noyd-public-sdk"
)

func main() {
	fmt.Println("==============================================")
	fmt.Println("NOYD Local Test Server")
	fmt.Println("ML-KEM-768 + ML-DSA-65 Post-Quantum Server")
	fmt.Println("==============================================")
	fmt.Println()

	// Create server configuration
	config := noyd.DefaultServerConfig()
	config.Address = "0.0.0.0"
	config.Port = 7879
	config.APIKeys = map[string]bool{
		"test-api-key": true,
		"dev-key":      true,
	}

	// Create and start server
	server, err := noyd.StartServer(config)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	fmt.Printf("Server started on http://localhost:%d\n", config.Port)
	fmt.Println()
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /health        - Health check")
	fmt.Println("  POST /handshake     - ML-KEM-768 + ML-DSA-65 handshake")
	fmt.Println("  POST /message       - Send encrypted message")
	fmt.Println("  GET  /message       - Receive encrypted message")
	fmt.Println("  GET  /session?id=X  - Get session info")
	fmt.Println("  DEL  /session?id=X  - Close session")
	fmt.Println()
	fmt.Printf("Test with: NOYD_ENDPOINT=http://localhost:%d go run ../examples/main.go\n", config.Port)
	fmt.Println()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println()
	fmt.Println("Shutting down server...")

	if err := server.Stop(); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	fmt.Println("Server stopped.")
}
