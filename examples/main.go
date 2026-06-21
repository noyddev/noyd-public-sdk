// main.go — NOYD Public SDK Example
// Demonstrates how to import the SDK and perform a connection/health check.

package main

import (
	"fmt"
	"log"
	"os"

	noyd "github.com/noyddev/noyd-public-sdk"
)

func main() {
	// Read API key from environment variable for security
	apiKey := os.Getenv("NOYD_DEVELOPER_KEY")
	if apiKey == "" {
		log.Fatal("NOYD_DEVELOPER_KEY environment variable is not set")
	}

	// Connect to the NOYD production server using API key authentication
	// The ConnectWithAPIKey function performs a post-quantum handshake
	// and includes the X-API-Key header in all telemetry requests.
	session, err := noyd.ConnectWithAPIKey("https://noyd-public-sdk.onrender.com", apiKey)
	if err != nil {
		log.Fatalf("Failed to connect to NOYD server: %v", err)
	}
	defer session.Close()

	// Print session info
	fmt.Printf("Connected successfully!\n")
	fmt.Printf("  Session ID: %s\n", session.ID)
	fmt.Printf("  Endpoint:   %s\n", session.Endpoint)

	// Retrieve and print telemetry report
	report := session.Telemetry()
	fmt.Printf("  Protocol:   %s\n", report.Metrics[0].Protocol)
	fmt.Printf("  Algorithm:  %s\n", report.Metrics[0].Algorithm)
	fmt.Printf("  Status:     %s\n", report.Metrics[0].Status)

	// Send a message through the post-quantum channel
	message := []byte("hello post-quantum world")
	if err := session.Send(message); err != nil {
		log.Fatalf("Send failed: %v", err)
	}
	fmt.Printf("Message sent: %s\n", string(message))

	// Receive a response from the server
	reply, err := session.Receive()
	if err != nil {
		log.Fatalf("Receive failed: %v", err)
	}
	fmt.Printf("Reply received: %s\n", string(reply))

	fmt.Println("Health check complete — SDK is working correctly.")
}
