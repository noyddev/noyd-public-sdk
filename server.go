// server.go — NOYD Backend Server Implementation
// Post-Quantum Cryptography server with ML-KEM-768 / ML-DSA-65
// Production-ready server for github.com/noyddev/noyd-public-sdk

package noyd

import (
	"context"
	crypto "crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// -----------------------------------------------------------------------------
// Server Configuration
// -----------------------------------------------------------------------------

// ServerConfig holds server configuration parameters.
type ServerConfig struct {
	Address      string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	APIKeys      map[string]bool // allowed API keys
}

// DefaultServerConfig returns default server configuration.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:      "0.0.0.0",
		Port:         7879,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		APIKeys:     map[string]bool{"test-api-key": true},
	}
}

// -----------------------------------------------------------------------------
// Server State
// -----------------------------------------------------------------------------

// Server represents a NOYD PQC server instance.
type Server struct {
	config            ServerConfig
	mlkemPublicKey    []byte                   // server's ML-KEM-768 public key for encapsulation
	mlkemPrivateKey   *mlkem768.PrivateKey     // server's ML-KEM-768 private key for decapsulation
	signingPublicKey  []byte                   // server's ML-DSA-65 public key
	signingPrivateKey *mldsa65.PrivateKey      // server's ML-DSA-65 private key for signing
	sessions          map[string]*ServerSession // active sessions
	mu                sync.RWMutex
	httpServer        *http.Server
}

// ServerSession represents an active server-side session.
type ServerSession struct {
	SessionID      string
	ClientPublicKey *mldsa65.PublicKey        // client's ML-DSA-65 public key
	SharedSecret   []byte                      // derived shared secret
	SessionKey     []byte                      // derived session key via HKDF
	SequenceNum    uint64
	CreatedAt      time.Time
	LastActivity   time.Time
}

// -----------------------------------------------------------------------------
// Server Lifecycle
// -----------------------------------------------------------------------------

// NewServer creates a new NOYD PQC server with generated ML-KEM-768 and ML-DSA-65 keys.
func NewServer(config ServerConfig) (*Server, error) {
	srv := &Server{
		config:  config,
		sessions: make(map[string]*ServerSession),
	}

	// Generate ML-KEM-768 keypair for key encapsulation
	log.Printf("[SERVER] Generating ML-KEM-768 keypair...")
	mlkemPkt, mlkemSkt, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM-768 keypair: %w", err)
	}
	srv.mlkemPrivateKey = mlkemSkt

	mlkemPubBytes, err := mlkemPkt.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ML-KEM-768 public key: %w", err)
	}
	srv.mlkemPublicKey = mlkemPubBytes

	// Generate ML-DSA-65 signing keypair for authentication
	log.Printf("[SERVER] Generating ML-DSA-65 signing keypair...")
	signingPk, signingSk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA-65 signing keypair: %w", err)
	}
	srv.signingPrivateKey = signingSk

	signingPubBytes, err := signingPk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ML-DSA-65 public key: %w", err)
	}
	srv.signingPublicKey = signingPubBytes

	log.Printf("[SERVER] Server initialized with ML-KEM-768 + ML-DSA-65")
	return srv, nil
}

// Start begins serving HTTP requests.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/handshake", s.handleHandshake)
	mux.HandleFunc("/message", s.handleMessage)
	mux.HandleFunc("/session", s.handleSession)

	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	log.Printf("[SERVER] Starting NOYD PQC server on %s", addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// -----------------------------------------------------------------------------
// HTTP Handlers
// -----------------------------------------------------------------------------

// handleHealth handles health check requests.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(HealthResponse{
		Status:    "healthy",
		Service:   "noyd-server",
		Protocol:  "ML-KEM-768+ML-DSA-65",
		Build:     "production-pqc",
		Timestamp: time.Now().UnixMicro(),
	})
}

// handleHandshake processes client hello and performs ML-KEM-768 encapsulation.
func (s *Server) handleHandshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify API key
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		apiKey = r.URL.Query().Get("api_key")
	}
	if !s.isValidAPIKey(apiKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Read and parse request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req HandshakeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Decode client hello
	clientHelloBytes, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		http.Error(w, "Invalid payload encoding", http.StatusBadRequest)
		return
	}

	var clientHello ClientHello
	if err := json.Unmarshal(clientHelloBytes, &clientHello); err != nil {
		http.Error(w, "Invalid client hello", http.StatusBadRequest)
		return
	}

	// Verify client public key
	clientPubKeyBytes, err := base64.StdEncoding.DecodeString(clientHello.ClientPublicKey)
	if err != nil {
		http.Error(w, "Invalid client public key", http.StatusBadRequest)
		return
	}

	clientPubKey := new(mldsa65.PublicKey)
	if err := clientPubKey.UnmarshalBinary(clientPubKeyBytes); err != nil {
		http.Error(w, "Invalid client public key format", http.StatusBadRequest)
		return
	}

	// Verify client signature over client hello
	signStart := time.Now()
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "Invalid signature encoding", http.StatusBadRequest)
		return
	}
	log.Printf("[SERVER] clientHelloBytes len=%d, sig len=%d", len(clientHelloBytes), len(sigBytes))
	log.Printf("[SERVER] clientHelloBytes: %x", clientHelloBytes[:int(math.Min(50, float64(len(clientHelloBytes))))])
	if !mldsa65.Verify(clientPubKey, clientHelloBytes, nil, sigBytes) {
		log.Printf("[SERVER] Verify failed!")
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}
	log.Printf("[SERVER] Client signature verified OK")
	verifyUs := time.Since(signStart).Microseconds()

	// Parse client's ML-KEM public key
	clientMLKEMPub := new(mlkem768.PublicKey)
	clientMLKEMPubBytes, err := base64.StdEncoding.DecodeString(clientHello.MLKEMPublicKey)
	if err != nil {
		http.Error(w, "Invalid client ML-KEM key encoding", http.StatusBadRequest)
		return
	}
	if err := clientMLKEMPub.Unpack(clientMLKEMPubBytes); err != nil {
		http.Error(w, "Invalid client ML-KEM key", http.StatusBadRequest)
		return
	}

	// Generate session ID
	sessionID := fmt.Sprintf("noyd-%d", time.Now().UnixNano())

	// Perform ML-KEM-768 encapsulation using client's public key
	encapsStart := time.Now()
	ciphertext := make([]byte, mlkem768.CiphertextSize)
	sharedSecret := make([]byte, mlkem768.SharedKeySize)
	clientMLKEMPub.EncapsulateTo(ciphertext, sharedSecret, nil)
	encapUs := time.Since(encapsStart).Microseconds()

	// Derive session key using HKDF
	sessionKey := hkdf.Extract(sha256.New, sharedSecret, []byte(sessionID))
	expandedKey := hkdf.Expand(sha256.New, sessionKey, []byte("noyd-session-v1"))
	sessionKeyBytes := make([]byte, 32)
	if _, err := io.ReadFull(expandedKey, sessionKeyBytes); err != nil {
		http.Error(w, "Key derivation failed", http.StatusInternalServerError)
		return
	}

	// Create server hello
	serverHello := ServerHello{
		MLKEMCiphertext: base64.StdEncoding.EncodeToString(ciphertext),
		ServerPublicKey: base64.StdEncoding.EncodeToString(s.signingPublicKey),
		SessionID:       sessionID,
		Timestamp:       time.Now().UnixMicro(),
	}

	// Sign (nonce + session_id) with server's ML-DSA-65 key
	// clientHello.Nonce is base64-encoded, so decode it first
	nonceBytes, err := base64.StdEncoding.DecodeString(clientHello.Nonce)
	if err != nil {
		log.Printf("[SERVER] Failed to decode nonce: %v", err)
		http.Error(w, "Invalid nonce encoding", http.StatusBadRequest)
		return
	}
	signBase := append(nonceBytes, []byte(sessionID)...)
	signature, err := s.signingPrivateKey.Sign(rand.Reader, signBase, crypto.Hash(0))
	if err != nil {
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}
	serverHello.Signature = base64.StdEncoding.EncodeToString(signature)

	// Store session
	s.mu.Lock()
	s.sessions[sessionID] = &ServerSession{
		SessionID:      sessionID,
		ClientPublicKey: clientPubKey,
		SharedSecret:   sharedSecret,
		SessionKey:     sessionKeyBytes,
		SequenceNum:    0,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}
	s.mu.Unlock()

	// Create response
	serverHelloBytes, err := json.Marshal(serverHello)
	if err != nil {
		http.Error(w, "Failed to marshal server hello", http.StatusInternalServerError)
		return
	}

	resp := HandshakeResponse{
		Type:      "server_hello",
		Payload:   base64.StdEncoding.EncodeToString(serverHelloBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)

	log.Printf("[SERVER] Handshake complete → session=%s verify_us=%d encap_us=%d",
		sessionID, verifyUs, encapUs)
}

// deriveMessageKey derives a unique session key for each message using HKDF.
func (s *Server) deriveMessageKey(sessionKey, sharedSecret []byte, seqNum uint64) ([]byte, error) {
	info := fmt.Sprintf("noyd-msg-key-v1-%d", seqNum)
	h := hkdf.New(sha256.New, sessionKey, sharedSecret, []byte(info))

	key := make([]byte, 32) // ChaCha20Poly1305 requires 32-byte key
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("failed to derive message key: %w", err)
	}
	return key, nil
}

// handleMessage handles encrypted message exchange.
func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = r.URL.Query().Get("session")
	}

	// Get session
	s.mu.Lock()
	session, exists := s.sessions[sessionID]
	if !exists {
		s.mu.Unlock()
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}
	session.LastActivity = time.Now()
	s.mu.Unlock()

	if r.Method == http.MethodGet {
		// Receive: return encrypted response
		s.handleMessageReceive(w, r, session)
	} else if r.Method == http.MethodPost {
		// Send: process encrypted message
		s.handleMessageSend(w, r, session, sessionID)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleMessageSend processes an encrypted message from the client.
func (s *Server) handleMessageSend(w http.ResponseWriter, r *http.Request, session *ServerSession, sessionID string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var msgReq struct {
		Type      string `json:"type"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := json.Unmarshal(body, &msgReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Decode payload
	payloadBytes, err := base64.StdEncoding.DecodeString(msgReq.Payload)
	if err != nil {
		http.Error(w, "Invalid payload encoding", http.StatusBadRequest)
		return
	}

	var encMsg EncryptedMessage
	if err := json.Unmarshal(payloadBytes, &encMsg); err != nil {
		http.Error(w, "Invalid encrypted message", http.StatusBadRequest)
		return
	}

	// Verify client signature
	sigData := append([]byte(encMsg.Ciphertext), make([]byte, 8)...)
	binary.BigEndian.PutUint64(sigData[len(sigData)-8:], encMsg.SequenceNum)

	sigBytes, err := base64.StdEncoding.DecodeString(msgReq.Signature)
	if err != nil {
		http.Error(w, "Invalid signature encoding", http.StatusBadRequest)
		return
	}
	if !mldsa65.Verify(session.ClientPublicKey, sigData, nil, sigBytes) {
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}

	// Decrypt the message
	ciphertext, err := base64.StdEncoding.DecodeString(encMsg.Ciphertext)
	if err != nil {
		http.Error(w, "Invalid ciphertext encoding", http.StatusBadRequest)
		return
	}

	nonce, err := base64.StdEncoding.DecodeString(encMsg.Nonce)
	if err != nil {
		http.Error(w, "Invalid nonce encoding", http.StatusBadRequest)
		return
	}

	msgKey, err := s.deriveMessageKey(session.SessionKey, session.SharedSecret, encMsg.SequenceNum)
	if err != nil {
		http.Error(w, "Key derivation failed", http.StatusInternalServerError)
		return
	}

	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		http.Error(w, "AEAD creation failed", http.StatusInternalServerError)
		return
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(sessionID))
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	// Update sequence number
	session.SequenceNum++

	log.Printf("[SERVER] Received message → session=%s bytes=%d seq=%d",
		sessionID, len(plaintext), encMsg.SequenceNum-1)

	// Create echo response (for demonstration - server echoes back)
	responseMsg := fmt.Sprintf("server received: %s", string(plaintext))

	// Encrypt response
	nonce, err = generateNonce(12) // ChaCha20Poly1305 uses 12-byte nonces
	if err != nil {
		http.Error(w, "Nonce generation failed", http.StatusInternalServerError)
		return
	}

	msgKey, err = s.deriveMessageKey(session.SessionKey, session.SharedSecret, session.SequenceNum)
	if err != nil {
		http.Error(w, "Key derivation failed", http.StatusInternalServerError)
		return
	}

	aead, err = chacha20poly1305.New(msgKey)
	if err != nil {
		http.Error(w, "AEAD creation failed", http.StatusInternalServerError)
		return
	}

	ciphertext = aead.Seal(nil, nonce, []byte(responseMsg), []byte(sessionID))
	session.SequenceNum++

	// Create response message with base64-encoded ciphertext first
	encResp := EncryptedMessage{
		Ciphertext:  base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		SequenceNum: session.SequenceNum - 1,
		Timestamp:   time.Now().UnixMicro(),
	}

	// Sign the base64-encoded ciphertext (same string used in encResp.Ciphertext)
	responseSigData := append([]byte(encResp.Ciphertext), make([]byte, 8)...)
	binary.BigEndian.PutUint64(responseSigData[len(responseSigData)-8:], session.SequenceNum-1)
	serverSig, err := s.signingPrivateKey.Sign(rand.Reader, responseSigData, crypto.Hash(0))
	if err != nil {
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}

	respBytes, err := json.Marshal(encResp)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	respPayload := map[string]interface{}{
		"type":      "encrypted_message",
		"payload":   base64.StdEncoding.EncodeToString(respBytes),
		"signature": base64.StdEncoding.EncodeToString(serverSig),
		"timestamp": time.Now().UnixMicro(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(respPayload)
}

// handleMessageReceive returns the next encrypted message to the client.
func (s *Server) handleMessageReceive(w http.ResponseWriter, r *http.Request, session *ServerSession) {
	// For this demo, we return a simple acknowledgment
	// In a real server, this would block until a message is available
	ack := map[string]interface{}{
		"type":      "ack",
		"session":   session.SessionID,
		"timestamp": time.Now().UnixMicro(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ack)
}

// handleSession handles session management requests.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("id")
	if sessionID == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	session, exists := s.sessions[sessionID]
	if !exists {
		s.mu.Unlock()
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodDelete {
		// Close session
		delete(s.sessions, sessionID)
		s.mu.Unlock()

		// Securely clear sensitive data
		for i := range session.SharedSecret {
			session.SharedSecret[i] = 0
		}
		for i := range session.SessionKey {
			session.SessionKey[i] = 0
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "closed"})
		log.Printf("[SERVER] Session closed → %s", sessionID)
	} else if r.Method == http.MethodGet {
		// Get session info
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"session_id":  session.SessionID,
			"created_at":  session.CreatedAt,
			"last_active": session.LastActivity,
		})
	} else {
		s.mu.Unlock()
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// isValidAPIKey checks if the provided API key is valid.
func (s *Server) isValidAPIKey(apiKey string) bool {
	if apiKey == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.APIKeys[apiKey]
}

// GetServerPublicKey returns the server's ML-KEM-768 public key for clients.
func (s *Server) GetServerPublicKey() string {
	return base64.StdEncoding.EncodeToString(s.mlkemPublicKey)
}

// GetSigningPublicKey returns the server's ML-DSA-65 public key for clients.
func (s *Server) GetSigningPublicKey() string {
	return base64.StdEncoding.EncodeToString(s.signingPublicKey)
}

// StartServer is a convenience function to start a server in a goroutine.
func StartServer(config ServerConfig) (*Server, error) {
	srv, err := NewServer(config)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := srv.Start(); err != nil {
			log.Printf("[SERVER] Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)
	return srv, nil
}

// CleanSessions removes expired sessions.
func (s *Server) CleanSessions(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.Sub(session.LastActivity) > maxAge {
			delete(s.sessions, id)
			log.Printf("[SERVER] Cleaned expired session → %s", id)
		}
	}
}

// SessionCount returns the number of active sessions.
func (s *Server) SessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
