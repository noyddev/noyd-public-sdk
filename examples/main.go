// main.go — NOYD Public SDK Example
// Demonstrates end-to-end PQC handshake with real ML-KEM-768 and ML-DSA-65.

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	noyd "github.com/noyddev/noyd-public-sdk"
)

func main() {
	// Configuration
	endpoint := os.Getenv("NOYD_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:7879" // Use local test server by default
	}

	apiKey := os.Getenv("NOYD_DEVELOPER_KEY")
	if apiKey == "" {
		apiKey = "test-api-key" // Default for local testing
	}

	fmt.Println("==============================================")
	fmt.Println("NOYD Public SDK — Post-Quantum Handshake Demo")
	fmt.Println("==============================================")
	fmt.Println()

	// Step 1: Connect with PQC handshake
	fmt.Println("[1] Initiating ML-KEM-768 + ML-DSA-65 handshake...")
	connectStart := time.Now()

	session, err := noyd.ConnectWithAPIKey(endpoint, apiKey)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	connectDuration := time.Since(connectStart)

	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("Error closing session: %v", err)
		}
	}()

	// Print session info
	fmt.Println()
	fmt.Println("[2] Handshake Complete!")
	fmt.Printf("    Session ID:     %s\n", session.ID)
	fmt.Printf("    Endpoint:       %s\n", session.Endpoint)
	fmt.Printf("    Connect Time:   %v\n", connectDuration)

	// Print telemetry metrics
	report := session.Telemetry()
	if len(report.Metrics) > 0 {
		m := report.Metrics[0]
		fmt.Println()
		fmt.Println("[3] Handshake Performance Metrics:")
		fmt.Printf("    Key Generation: %d µs\n", m.KeyGenUs)
		fmt.Printf("    Encapsulation:  %d µs\n", m.EncapUs)
		fmt.Printf("    Decapsulation:  %d µs\n", m.DecapUs)
		fmt.Printf("    Signing:        %d µs\n", m.SignUs)
		fmt.Printf("    Verification:   %d µs\n", m.VerifyUs)
		fmt.Printf("    Protocol:       %s\n", m.Protocol)
		fmt.Printf("    Algorithm:      %s\n", m.Algorithm)
		fmt.Printf("    Status:          %s\n", m.Status)
	}

	// Step 2: Send an encrypted message and get server response
	fmt.Println()
	fmt.Println("[4] Sending encrypted message...")
	testMessage := "hello post-quantum world"
	fmt.Printf("    Plaintext: %q\n", testMessage)

	if err := session.Send([]byte(testMessage)); err != nil {
		log.Fatalf("Send failed: %v", err)
	}
	fmt.Println("    Message sent and response received successfully!")

	fmt.Println()
	fmt.Println("==============================================")
	fmt.Println("PQC Handshake Demo Complete — All operations")
	fmt.Println("performed with real ML-KEM-768 encapsulation")
	fmt.Println("and ML-DSA-65 signature verification.")
	fmt.Println("==============================================")
}
