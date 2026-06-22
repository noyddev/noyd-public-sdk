// noyd.go — NOYD Public SDK Facade
// Post-Quantum Cryptography interface for ML-KEM-768 / ML-DSA-65
// Production-ready public SDK for github.com/noyddev/noyd-public-sdk

package noyd

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// -----------------------------------------------------------------------------
// Sentinel Errors
// -----------------------------------------------------------------------------
var (
	ErrConnectionFailed  = errors.New("noyd: connection failed")
	ErrHandshakeTimeout = errors.New("noyd: handshake timeout")
	ErrSendFailed       = errors.New("noyd: send failed")
	ErrRecvFailed       = errors.New("noyd: receive failed")
	ErrCryptoFailure    = errors.New("noyd: cryptographic operation failed")
	ErrInvalidHandle    = errors.New("noyd: invalid session handle")
	ErrNotConnected     = errors.New("noyd: not connected")
	ErrMissingAPIKey    = errors.New("noyd: API key is required")
	ErrInvalidResponse  = errors.New("noyd: invalid server response")
	ErrVerifyFailed     = errors.New("noyd: signature verification failed")
	ErrDecapFailed      = errors.New("noyd: decapsulation failed")
	ErrEncapFailed      = errors.New("noyd: encapsulation failed")
	ErrKeyGenFailed     = errors.New("noyd: key generation failed")
	ErrSigningFailed    = errors.New("noyd: signing failed")
	ErrEncryptFailed    = errors.New("noyd: encryption failed")
	ErrDecryptFailed    = errors.New("noyd: decryption failed")
)

// -----------------------------------------------------------------------------
// Telemetry Structures
// -----------------------------------------------------------------------------

// TelemetryMetric encapsulates PQC handshake performance data.
type TelemetryMetric struct {
	Timestamp  int64  `json:"timestamp"`
	Protocol   string `json:"protocol"`
	Algorithm  string `json:"algorithm"`
	KeyGenUs   int64  `json:"key_generation_us"`
	EncapUs    int64  `json:"encapsulation_us"`
	DecapUs    int64  `json:"decapsulation_us"`
	SignUs     int64  `json:"signing_us"`
	VerifyUs   int64  `json:"verification_us"`
	SessionID  string `json:"session_id"`
	Status     string `json:"status"`
}

// TelemetryReport aggregates session metrics.
type TelemetryReport struct {
	SessionID   string            `json:"session_id"`
	Endpoint    string            `json:"endpoint"`
	ConnectedAt time.Time         `json:"connected_at"`
	Metrics     []TelemetryMetric `json:"metrics"`
}

// -----------------------------------------------------------------------------
// Handshake Protocol Structures
// -----------------------------------------------------------------------------

// ClientHello is sent by the client to initiate the PQC handshake.
type ClientHello struct {
	MLKEMPublicKey   string `json:"mlkem_public_key"`   // base64-encoded ML-KEM-768 public key
	ClientPublicKey  string `json:"client_public_key"` // base64-encoded ML-DSA-65 public key for authentication
	Nonce            string `json:"nonce"`             // random nonce for freshness
	Timestamp        int64  `json:"timestamp"`
	APIKey           string `json:"-"`                 // not serialized, used in header
}

// ServerHello is sent by the server in response to ClientHello.
type ServerHello struct {
	MLKEMCiphertext  string `json:"mlkem_ciphertext"`  // base64-encoded ML-KEM-768 ciphertext
	ServerPublicKey  string `json:"server_public_key"` // base64-encoded ML-DSA-65 public key
	Signature        string `json:"signature"`         // base64-encoded ML-DSA-65 signature over (nonce + session_id)
	SessionID        string `json:"session_id"`
	Timestamp        int64  `json:"timestamp"`
}

// HandshakeRequest wraps the handshake payload for JSON transport.
type HandshakeRequest struct {
	Type      string `json:"type"`
	Payload   string `json:"payload"`   // base64-encoded payload
	Signature string `json:"signature"` // base64-encoded ML-DSA-65 signature
	Timestamp int64  `json:"timestamp"`
}

// HandshakeResponse wraps the server's response.
type HandshakeResponse struct {
	Type      string `json:"type"`
	Payload   string `json:"payload"` // base64-encoded ServerHello
	Signature string `json:"signature"`
}

// EncryptedMessage represents an encrypted message in the protocol.
type EncryptedMessage struct {
	Ciphertext  string `json:"ciphertext"`  // base64-encoded ciphertext (nonce + ciphertext + tag)
	Nonce       string `json:"nonce"`       // base64-encoded nonce
	SequenceNum uint64 `json:"sequence_num"`
	Timestamp   int64  `json:"timestamp"`
}

// Session represents a post-quantum secured NOYD session.
type Session struct {
	ID              string
	Endpoint        string
	Connected       bool
	Metrics         []TelemetryMetric
	sharedSecret    []byte        // derived ML-KEM-768 shared secret
	clientSigningKey *mldsa65.PrivateKey // client's ML-DSA-65 signing key
	serverPublicKey  *mldsa65.PublicKey   // server's ML-DSA-65 public key for verification
	sessionKey      []byte        // derived session key via HKDF
	sequenceNum     uint64
	mu              sync.RWMutex
	httpClient      *http.Client
	apiKey          string
	serverPublicKeyPEM string // stored for reference
}

// -----------------------------------------------------------------------------
// SDK Configuration
// -----------------------------------------------------------------------------

// Config holds SDK configuration parameters.
type Config struct {
	APIKey       string
	TimeoutMs    uint32
	RetryCount   int
	RetryDelayMs int
}

// DefaultConfig returns the default SDK configuration.
func DefaultConfig() Config {
	return Config{
		TimeoutMs:    10000,
		RetryCount:   3,
		RetryDelayMs: 500,
	}
}

// NewConfigWithAPIKey returns a Config with the API key pre-set.
func NewConfigWithAPIKey(apiKey string) Config {
	return Config{
		APIKey:       apiKey,
		TimeoutMs:    10000,
		RetryCount:   3,
		RetryDelayMs: 500,
	}
}

// -----------------------------------------------------------------------------
// Connect Functions
// -----------------------------------------------------------------------------

// Connect establishes a post-quantum-secured connection to a NOYD node.
// Performs ML-KEM-768 encapsulation and ML-DSA-65 signing handshake.
// Returns an active Session or a typed sentinel error.
func Connect(endpoint string) (*Session, error) {
	return ConnectWithConfig(endpoint, DefaultConfig())
}

// ConnectWithAPIKey connects using an API key.
func ConnectWithAPIKey(endpoint, apiKey string) (*Session, error) {
	if apiKey == "" {
		return nil, ErrMissingAPIKey
	}
	cfg := NewConfigWithAPIKey(apiKey)
	return ConnectWithConfig(endpoint, cfg)
}

// ConnectWithConfig connects with explicit SDK configuration.
func ConnectWithConfig(endpoint string, cfg Config) (*Session, error) {
	if endpoint == "" {
		return nil, ErrConnectionFailed
	}

	if cfg.APIKey == "" {
		return nil, ErrMissingAPIKey
	}

	session, err := performPQCHandshake(endpoint, cfg)
	if err != nil {
		return nil, err
	}

	log.Printf("[NOYD] Session established → id=%s endpoint=%s", session.ID, endpoint)
	return session, nil
}

// -----------------------------------------------------------------------------
// PQC Handshake Implementation
// -----------------------------------------------------------------------------

// generateNonce creates a random nonce for freshness.
func generateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// performPQCHandshake performs the actual ML-KEM-768 + ML-DSA-65 handshake.
func performPQCHandshake(endpoint string, cfg Config) (*Session, error) {
	start := time.Now()

	// Step 1: Generate ML-KEM-768 keypair for key encapsulation
	keyGenStart := time.Now()
	pk, sk, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: ML-KEM-768 key generation failed: %v", ErrKeyGenFailed, err)
	}
	keyGenUs := time.Since(keyGenStart).Microseconds()

	// Step 2: Generate ML-DSA-65 signing keypair for authentication
	signStart := time.Now()
	signingPk, signingSk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: ML-DSA-65 key generation failed: %v", ErrKeyGenFailed, err)
	}
	signUs := time.Since(signStart).Microseconds()

	// Step 3: Create client hello with public keys
	nonce, err := generateNonce(32)
	if err != nil {
		return nil, err
	}

	// Marshal ML-KEM-768 public key and ML-DSA-65 public key to bytes
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ML-KEM public key: %w", err)
	}
	signingPkBytes, err := signingPk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing public key: %w", err)
	}

	clientHello := ClientHello{
		MLKEMPublicKey:  base64.StdEncoding.EncodeToString(pkBytes),
		ClientPublicKey: base64.StdEncoding.EncodeToString(signingPkBytes),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Timestamp:       time.Now().UnixMicro(),
		APIKey:          cfg.APIKey,
	}

	// Serialize and encode client hello
	helloBytes, err := json.Marshal(clientHello)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client hello: %w", err)
	}

	// Sign the client hello with ML-DSA-65
	signStart = time.Now()
	signature, err := signingSk.Sign(rand.Reader, helloBytes, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to sign client hello: %v", ErrSigningFailed, err)
	}
	signUs += time.Since(signStart).Microseconds()

	// Step 4: Send handshake request to server
	httpClient := &http.Client{Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond}

	reqBody := HandshakeRequest{
		Type:      "client_hello",
		Payload:   base64.StdEncoding.EncodeToString(helloBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
		Timestamp: time.Now().UnixMicro(),
	}
	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint+"/handshake", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", cfg.APIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: handshake request failed: %v", ErrConnectionFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: server returned status %d", ErrConnectionFailed, resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var handshakeResp HandshakeResponse
	if err := json.Unmarshal(respBytes, &handshakeResp); err != nil {
		return nil, fmt.Errorf("%w: invalid response format: %v", ErrInvalidResponse, err)
	}

	// Step 5: Decode and verify server hello
	serverHelloBytes, err := base64.StdEncoding.DecodeString(handshakeResp.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode server payload: %v", ErrInvalidResponse, err)
	}

	var serverHello ServerHello
	if err := json.Unmarshal(serverHelloBytes, &serverHello); err != nil {
		return nil, fmt.Errorf("%w: failed to parse server hello: %v", ErrInvalidResponse, err)
	}

	// Step 6: Verify server's ML-DSA-65 signature
	verifyStart := time.Now()
	serverPubKeyBytes, err := base64.StdEncoding.DecodeString(serverHello.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid server public key encoding: %v", ErrInvalidResponse, err)
	}

	serverPubKey := new(mldsa65.PublicKey)
	if err := serverPubKey.UnmarshalBinary(serverPubKeyBytes); err != nil {
		return nil, fmt.Errorf("%w: failed to parse server public key: %v", ErrInvalidResponse, err)
	}

	// Verify signature over (nonce + session_id)
	nonceBytes, err := base64.StdEncoding.DecodeString(clientHello.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid nonce encoding: %v", ErrInvalidResponse, err)
	}
	sigBase := append(nonceBytes, []byte(serverHello.SessionID)...)
	sigBytes, err := base64.StdEncoding.DecodeString(serverHello.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding: %v", ErrInvalidResponse, err)
	}
	if !mldsa65.Verify(serverPubKey, sigBase, nil, sigBytes) {
		return nil, fmt.Errorf("%w: server signature verification failed", ErrVerifyFailed)
	}
	verifyUs := time.Since(verifyStart).Microseconds()

	// Step 7: Perform ML-KEM-768 decapsulation to derive shared secret
	decapsStart := time.Now()
	ciphertextBytes, err := base64.StdEncoding.DecodeString(serverHello.MLKEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ciphertext encoding: %v", ErrInvalidResponse, err)
	}

	sharedSecret := make([]byte, mlkem768.SharedKeySize)
	sk.DecapsulateTo(sharedSecret, ciphertextBytes)
	decapUs := time.Since(decapsStart).Microseconds()

	// Step 8: Derive session key using HKDF
	sessionKey := hkdf.Extract(sha256.New, sharedSecret, []byte(serverHello.SessionID))
	expandedKey := hkdf.Expand(sha256.New, sessionKey, []byte("noyd-session-v1"))

	sessionKeyBytes := make([]byte, 32) // 256-bit key for ChaCha20Poly1305
	if _, err := io.ReadFull(expandedKey, sessionKeyBytes); err != nil {
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	// Record metrics
	totalUs := time.Since(start).Microseconds()
	metric := TelemetryMetric{
		Timestamp:  time.Now().UnixMicro(),
		Protocol:   "ML-KEM-768",
		Algorithm:  "ML-DSA-65",
		KeyGenUs:   keyGenUs,
		EncapUs:    0, // client doesn't encapsulate, server does
		DecapUs:    decapUs,
		SignUs:     signUs,
		VerifyUs:   verifyUs,
		SessionID:  serverHello.SessionID,
		Status:     "ESTABLISHED",
	}

	log.Printf("[NOYD] PQC handshake complete → total_us=%d session_id=%s", totalUs, serverHello.SessionID)

	return &Session{
		ID:              serverHello.SessionID,
		Endpoint:        endpoint,
		Connected:       true,
		Metrics:         []TelemetryMetric{metric},
		sharedSecret:    sharedSecret,
		clientSigningKey: signingSk,
		serverPublicKey:  serverPubKey,
		sessionKey:      sessionKeyBytes,
		sequenceNum:     0,
		httpClient:      httpClient,
		apiKey:          cfg.APIKey,
		serverPublicKeyPEM: serverHello.ServerPublicKey,
	}, nil
}

// -----------------------------------------------------------------------------
// Session Methods
// -----------------------------------------------------------------------------

// deriveMessageKey derives a unique session key for each message using HKDF.
func (s *Session) deriveMessageKey(seqNum uint64) ([]byte, error) {
	info := fmt.Sprintf("noyd-msg-key-v1-%d", seqNum)
	h := hkdf.New(sha256.New, s.sessionKey, s.sharedSecret, []byte(info))

	key := make([]byte, 32) // ChaCha20Poly1305 requires 32-byte key
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("failed to derive message key: %w", err)
	}
	return key, nil
}

// Send delivers data through the post-quantum channel with encryption and signing.
func (s *Session) Send(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.Connected {
		return ErrNotConnected
	}

	if len(data) == 0 {
		return ErrSendFailed
	}

	// Derive message-specific key
	msgKey, err := s.deriveMessageKey(s.sequenceNum)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEncryptFailed, err)
	}

	// Generate random nonce for this message
	nonce, err := generateNonce(12) // ChaCha20Poly1305 uses 12-byte nonces
	if err != nil {
		return fmt.Errorf("%w: failed to generate nonce: %v", ErrEncryptFailed, err)
	}

	// Encrypt the message using ChaCha20Poly1305
	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return fmt.Errorf("%w: failed to create AEAD: %v", ErrEncryptFailed, err)
	}

	ciphertext := aead.Seal(nil, nonce, data, []byte(s.ID))
	s.sequenceNum++

	// Sign the ciphertext (using base64-encoded ciphertext to match server)
	signStart := time.Now()
	encMsg := EncryptedMessage{
		Ciphertext:  base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		SequenceNum: s.sequenceNum - 1,
		Timestamp:   time.Now().UnixMicro(),
	}
	sigData := append([]byte(encMsg.Ciphertext), make([]byte, 8)...)
	binary.BigEndian.PutUint64(sigData[len(sigData)-8:], s.sequenceNum-1)
	log.Printf("[CLIENT] Signing message for transmission")
	signature, err := s.clientSigningKey.Sign(rand.Reader, sigData, crypto.Hash(0))
	signUs := time.Since(signStart).Microseconds()

	if err != nil {
		return fmt.Errorf("%w: failed to sign message: %v", ErrSigningFailed, err)
	}

	msgBytes, err := json.Marshal(encMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted message: %w", err)
	}

	// Create request body
	reqBody := map[string]interface{}{
		"type":      "encrypted_message",
		"payload":   base64.StdEncoding.EncodeToString(msgBytes),
		"signature": base64.StdEncoding.EncodeToString(signature),
		"timestamp": time.Now().UnixMicro(),
	}
	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send to server
	httpClient := &http.Client{Timeout: 5 * time.Second}
	endpoint := s.Endpoint
	if s.Endpoint == "" {
		endpoint = "https://noyd-public-sdk.onrender.com"
	}

	req, err := http.NewRequest("POST", endpoint+"/message", bytes.NewReader(reqBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", s.apiKey)
	req.Header.Set("X-Session-ID", s.ID)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: send request failed: %v", ErrSendFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: server returned status %d", ErrSendFailed, resp.StatusCode)
	}

	// Read the server's encrypted response (server echoes response in POST response)
	var responseBody struct {
		Type      string `json:"type"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	responseBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response: %w", readErr)
	}
	if unmarshalErr := json.Unmarshal(responseBytes, &responseBody); unmarshalErr != nil {
		return fmt.Errorf("%w: invalid response format: %v", ErrInvalidResponse, unmarshalErr)
	}

	// Decode and verify the message
	responsePayload, decodeErr := base64.StdEncoding.DecodeString(responseBody.Payload)
	if decodeErr != nil {
		return fmt.Errorf("%w: failed to decode payload: %v", ErrInvalidResponse, decodeErr)
	}

	var responseMsg EncryptedMessage
	if unmarshalErr := json.Unmarshal(responsePayload, &responseMsg); unmarshalErr != nil {
		return fmt.Errorf("%w: failed to parse encrypted message: %v", ErrInvalidResponse, unmarshalErr)
	}

	// Verify server's signature
	responseSigData := append([]byte(responseMsg.Ciphertext), make([]byte, 8)...)
	binary.BigEndian.PutUint64(responseSigData[len(responseSigData)-8:], responseMsg.SequenceNum)

	responseSigBytes, sigDecodeErr := base64.StdEncoding.DecodeString(responseBody.Signature)
	if sigDecodeErr != nil {
		return fmt.Errorf("%w: invalid signature encoding: %v", ErrInvalidResponse, sigDecodeErr)
	}
	if !mldsa65.Verify(s.serverPublicKey, responseSigData, nil, responseSigBytes) {
		return fmt.Errorf("%w: server signature verification failed", ErrVerifyFailed)
	}

	// Decrypt the message
	responseCiphertext, cipherErr := base64.StdEncoding.DecodeString(responseMsg.Ciphertext)
	if cipherErr != nil {
		return fmt.Errorf("%w: failed to decode ciphertext: %v", ErrDecryptFailed, cipherErr)
	}

	responseNonce, nonceErr := base64.StdEncoding.DecodeString(responseMsg.Nonce)
	if nonceErr != nil {
		return fmt.Errorf("%w: failed to decode nonce: %v", ErrDecryptFailed, nonceErr)
	}

	responseKey, keyErr := s.deriveMessageKey(responseMsg.SequenceNum)
	if keyErr != nil {
		return fmt.Errorf("%w: %v", ErrDecryptFailed, keyErr)
	}

	responseAead, aeadErr := chacha20poly1305.New(responseKey)
	if aeadErr != nil {
		return fmt.Errorf("%w: failed to create AEAD: %v", ErrDecryptFailed, aeadErr)
	}

	plaintext, decryptErr := responseAead.Open(nil, responseNonce, responseCiphertext, []byte(s.ID))
	if decryptErr != nil {
		return fmt.Errorf("%w: decryption failed: %v", ErrDecryptFailed, decryptErr)
	}

	log.Printf("[NOYD] Received response → session=%s bytes=%d seq=%d", s.ID, len(plaintext), responseMsg.SequenceNum)

	// Update telemetry with signing time
	s.Metrics[len(s.Metrics)-1].SignUs += signUs

	log.Printf("[NOYD] Send → session=%s bytes=%d seq=%d", s.ID, len(data), s.sequenceNum-1)
	return nil
}

// Receive waits for the next message from the peer with decryption and verification.
func (s *Session) Receive() ([]byte, error) {
	s.mu.RLock()
	if !s.Connected {
		s.mu.RUnlock()
		return nil, ErrNotConnected
	}
	s.mu.RUnlock()

	// Request next message from server
	httpClient := &http.Client{Timeout: 10 * time.Second}
	endpoint := s.Endpoint
	if s.Endpoint == "" {
		endpoint = "https://noyd-public-sdk.onrender.com"
	}

	req, err := http.NewRequest("GET", endpoint+"/message?session="+s.ID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-API-Key", s.apiKey)
	req.Header.Set("X-Session-ID", s.ID)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: receive request failed: %v", ErrRecvFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: server returned status %d", ErrRecvFailed, resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var msgResp struct {
		Type      string `json:"type"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(respBytes, &msgResp); err != nil {
		return nil, fmt.Errorf("%w: invalid response format: %v", ErrInvalidResponse, err)
	}

	// Decode and verify the message
	payloadBytes, err := base64.StdEncoding.DecodeString(msgResp.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode payload: %v", ErrInvalidResponse, err)
	}

	var encMsg EncryptedMessage
	if err := json.Unmarshal(payloadBytes, &encMsg); err != nil {
		return nil, fmt.Errorf("%w: failed to parse encrypted message: %v", ErrInvalidResponse, err)
	}

	// Verify server's signature
	sigData := append([]byte(encMsg.Ciphertext), make([]byte, 8)...)
	binary.BigEndian.PutUint64(sigData[len(sigData)-8:], encMsg.SequenceNum)

	sigBytes, err := base64.StdEncoding.DecodeString(msgResp.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding: %v", ErrInvalidResponse, err)
	}
	if !mldsa65.Verify(s.serverPublicKey, sigData, nil, sigBytes) {
		return nil, fmt.Errorf("%w: server message verification failed", ErrVerifyFailed)
	}

	// Decrypt the message
	ciphertext, err := base64.StdEncoding.DecodeString(encMsg.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode ciphertext: %v", ErrDecryptFailed, err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encMsg.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode nonce: %v", ErrDecryptFailed, err)
	}

	msgKey, err := s.deriveMessageKey(encMsg.SequenceNum)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}

	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create AEAD: %v", ErrDecryptFailed, err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(s.ID))
	if err != nil {
		return nil, fmt.Errorf("%w: decryption failed: %v", ErrDecryptFailed, err)
	}

	log.Printf("[NOYD] Receive → session=%s bytes=%d seq=%d", s.ID, len(plaintext), encMsg.SequenceNum)
	return plaintext, nil
}

// Telemetry returns the session's telemetry report.
func (s *Session) Telemetry() TelemetryReport {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return TelemetryReport{
		SessionID:   s.ID,
		Endpoint:    s.Endpoint,
		ConnectedAt: time.Now(),
		Metrics:     s.Metrics,
	}
}

// Close terminates the session gracefully.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.Connected {
		return nil
	}

	// Securely clear sensitive data
	if s.sharedSecret != nil {
		for i := range s.sharedSecret {
			s.sharedSecret[i] = 0
		}
	}
	if s.sessionKey != nil {
		for i := range s.sessionKey {
			s.sessionKey[i] = 0
		}
	}

	s.Connected = false
	log.Printf("[NOYD] Session closed → id=%s", s.ID)
	return nil
}

// -----------------------------------------------------------------------------
// Health Check (Render Deployment)
// -----------------------------------------------------------------------------

// HealthResponse represents the health check endpoint response.
type HealthResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	Protocol  string `json:"protocol"`
	Build     string `json:"build"`
	Timestamp int64  `json:"timestamp"`
}

// HealthCheckHandler returns an HTTP handler for Render health checks.
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(HealthResponse{
		Status:    "healthy",
		Service:   "noyd-public-sdk",
		Protocol:  "ML-KEM-768+ML-DSA-65",
		Build:     "production-pqc",
		Timestamp: time.Now().UnixMicro(),
	})
}
