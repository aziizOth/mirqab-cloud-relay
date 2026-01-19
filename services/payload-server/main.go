// Mirqab Cloud Relay - Payload Hosting Server
// Secure payload storage and delivery service with MinIO backend

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Configuration from environment
type Config struct {
	// Server settings
	ListenAddr  string
	MetricsPort string
	TenantID    string

	// MinIO settings
	MinioEndpoint  string
	MinioAccessKey string
	MinioSecretKey string
	MinioUseSSL    bool
	MinioBucket    string

	// Security settings
	AdminToken     string
	SigningSecret  string
	MaxPayloadSize int64 // bytes

	// Limits
	DefaultTTLHours    int
	MaxDownloadsPerURL int
}

func loadConfig() *Config {
	maxSize, _ := strconv.ParseInt(os.Getenv("MAX_PAYLOAD_SIZE"), 10, 64)
	if maxSize == 0 {
		maxSize = 100 * 1024 * 1024 // 100MB default
	}

	ttl, _ := strconv.Atoi(os.Getenv("DEFAULT_TTL_HOURS"))
	if ttl == 0 {
		ttl = 24
	}

	maxDownloads, _ := strconv.Atoi(os.Getenv("MAX_DOWNLOADS_PER_URL"))
	if maxDownloads == 0 {
		maxDownloads = 100
	}

	return &Config{
		ListenAddr:         getEnv("LISTEN_ADDR", ":8080"),
		MetricsPort:        getEnv("METRICS_PORT", "9092"),
		TenantID:           getEnv("TENANT_ID", "default"),
		MinioEndpoint:      getEnv("MINIO_ENDPOINT", "minio:9000"),
		MinioAccessKey:     getEnv("MINIO_ACCESS_KEY", "minioadmin"),
		MinioSecretKey:     getEnv("MINIO_SECRET_KEY", "minioadmin"),
		MinioUseSSL:        os.Getenv("MINIO_USE_SSL") == "true",
		MinioBucket:        getEnv("MINIO_BUCKET", "payloads"),
		AdminToken:         getEnv("ADMIN_TOKEN", ""),
		SigningSecret:      getEnv("SIGNING_SECRET", "change-me-in-production"),
		MaxPayloadSize:     maxSize,
		DefaultTTLHours:    ttl,
		MaxDownloadsPerURL: maxDownloads,
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// PayloadMetadata stores information about uploaded payloads
type PayloadMetadata struct {
	PayloadID     string            `json:"payload_id"`
	TenantID      string            `json:"tenant_id"`
	Filename      string            `json:"filename"`
	ContentType   string            `json:"content_type"`
	SizeBytes     int64             `json:"size_bytes"`
	SHA256Hash    string            `json:"sha256_hash"`
	UploadedAt    time.Time         `json:"uploaded_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
	MaxDownloads  int               `json:"max_downloads"`
	DownloadCount int               `json:"download_count"`
	ObjectKey     string            `json:"object_key"`
	Metadata      map[string]string `json:"metadata"`
}

// PayloadStore manages payload metadata
type PayloadStore struct {
	mu       sync.RWMutex
	payloads map[string]*PayloadMetadata // payloadID -> metadata
}

func NewPayloadStore() *PayloadStore {
	return &PayloadStore{
		payloads: make(map[string]*PayloadMetadata),
	}
}

func (s *PayloadStore) Add(p *PayloadMetadata) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payloads[p.PayloadID] = p
}

func (s *PayloadStore) Get(payloadID string) (*PayloadMetadata, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.payloads[payloadID]
	return p, ok
}

func (s *PayloadStore) Delete(payloadID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.payloads, payloadID)
}

func (s *PayloadStore) IncrementDownloads(payloadID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.payloads[payloadID]; ok {
		p.DownloadCount++
		return p.DownloadCount
	}
	return 0
}

func (s *PayloadStore) List(tenantID string) []*PayloadMetadata {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*PayloadMetadata
	for _, p := range s.payloads {
		if p.TenantID == tenantID {
			result = append(result, p)
		}
	}
	return result
}

// Prometheus metrics
var (
	uploadsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "payload_uploads_total",
			Help: "Total number of payload uploads",
		},
		[]string{"tenant_id", "status"},
	)

	downloadsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "payload_downloads_total",
			Help: "Total number of payload downloads",
		},
		[]string{"tenant_id", "status"},
	)

	uploadBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "payload_upload_bytes_total",
			Help: "Total bytes uploaded",
		},
		[]string{"tenant_id"},
	)

	downloadBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "payload_download_bytes_total",
			Help: "Total bytes downloaded",
		},
		[]string{"tenant_id"},
	)

	storageUsedBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "payload_storage_used_bytes",
			Help: "Current storage used by tenant",
		},
		[]string{"tenant_id"},
	)

	activePayloads = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "payload_active_count",
			Help: "Number of active payloads",
		},
		[]string{"tenant_id"},
	)
)

func init() {
	prometheus.MustRegister(uploadsTotal)
	prometheus.MustRegister(downloadsTotal)
	prometheus.MustRegister(uploadBytes)
	prometheus.MustRegister(downloadBytes)
	prometheus.MustRegister(storageUsedBytes)
	prometheus.MustRegister(activePayloads)
}

// PayloadServer is the main server struct
type PayloadServer struct {
	config      *Config
	minioClient *minio.Client
	store       *PayloadStore
}

func NewPayloadServer(config *Config) (*PayloadServer, error) {
	// Initialize MinIO client
	minioClient, err := minio.New(config.MinioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.MinioAccessKey, config.MinioSecretKey, ""),
		Secure: config.MinioUseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %w", err)
	}

	return &PayloadServer{
		config:      config,
		minioClient: minioClient,
		store:       NewPayloadStore(),
	}, nil
}

func (s *PayloadServer) ensureBucket(ctx context.Context) error {
	exists, err := s.minioClient.BucketExists(ctx, s.config.MinioBucket)
	if err != nil {
		return fmt.Errorf("failed to check bucket: %w", err)
	}
	if !exists {
		err = s.minioClient.MakeBucket(ctx, s.config.MinioBucket, minio.MakeBucketOptions{})
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}
		log.Printf("Created bucket: %s", s.config.MinioBucket)
	}
	return nil
}

// generatePayloadID creates a unique payload identifier
func generatePayloadID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateSignedURL creates a time-limited signed download URL
func (s *PayloadServer) generateSignedURL(payloadID string, expiresAt time.Time) string {
	message := fmt.Sprintf("%s:%d", payloadID, expiresAt.Unix())
	mac := hmac.New(sha256.New, []byte(s.config.SigningSecret))
	mac.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("/download/%s?expires=%d&sig=%s",
		payloadID, expiresAt.Unix(), signature)
}

// verifySignedURL validates a signed download URL
func (s *PayloadServer) verifySignedURL(payloadID string, expires int64, signature string) bool {
	message := fmt.Sprintf("%s:%d", payloadID, expires)
	mac := hmac.New(sha256.New, []byte(s.config.SigningSecret))
	mac.Write([]byte(message))
	expectedSig := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSig))
}

// authMiddleware validates admin authentication
func (s *PayloadServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")

		if token == "" || token != s.config.AdminToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// handleUpload handles payload uploads
func (s *PayloadServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form
	err := r.ParseMultipartForm(s.config.MaxPayloadSize)
	if err != nil {
		uploadsTotal.WithLabelValues(s.config.TenantID, "error").Inc()
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		uploadsTotal.WithLabelValues(s.config.TenantID, "error").Inc()
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Check file size
	if header.Size > s.config.MaxPayloadSize {
		uploadsTotal.WithLabelValues(s.config.TenantID, "rejected").Inc()
		http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Read file and calculate hash
	content, err := io.ReadAll(file)
	if err != nil {
		uploadsTotal.WithLabelValues(s.config.TenantID, "error").Inc()
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	hash := sha256.Sum256(content)
	hashHex := hex.EncodeToString(hash[:])

	// Verify hash if provided
	providedHash := r.FormValue("sha256_hash")
	if providedHash != "" && providedHash != hashHex {
		uploadsTotal.WithLabelValues(s.config.TenantID, "rejected").Inc()
		http.Error(w, "Hash mismatch", http.StatusBadRequest)
		return
	}

	// Parse TTL
	ttlHours := s.config.DefaultTTLHours
	if ttlStr := r.FormValue("expires_hours"); ttlStr != "" {
		if parsed, err := strconv.Atoi(ttlStr); err == nil && parsed > 0 {
			ttlHours = parsed
		}
	}

	// Parse max downloads
	maxDownloads := s.config.MaxDownloadsPerURL
	if maxStr := r.FormValue("max_downloads"); maxStr != "" {
		if parsed, err := strconv.Atoi(maxStr); err == nil && parsed > 0 {
			maxDownloads = parsed
		}
	}

	// Generate payload ID and object key
	payloadID := generatePayloadID()
	objectKey := fmt.Sprintf("%s/%s/%s", s.config.TenantID, payloadID, header.Filename)

	// Upload to MinIO
	ctx := r.Context()
	_, err = s.minioClient.PutObject(ctx, s.config.MinioBucket, objectKey,
		strings.NewReader(string(content)), int64(len(content)),
		minio.PutObjectOptions{
			ContentType: header.Header.Get("Content-Type"),
		})
	if err != nil {
		uploadsTotal.WithLabelValues(s.config.TenantID, "error").Inc()
		log.Printf("MinIO upload failed: %v", err)
		http.Error(w, "Storage error", http.StatusInternalServerError)
		return
	}

	// Parse custom metadata
	customMeta := make(map[string]string)
	if metaStr := r.FormValue("metadata"); metaStr != "" {
		json.Unmarshal([]byte(metaStr), &customMeta)
	}

	// Create metadata record
	now := time.Now()
	expiresAt := now.Add(time.Duration(ttlHours) * time.Hour)

	metadata := &PayloadMetadata{
		PayloadID:     payloadID,
		TenantID:      s.config.TenantID,
		Filename:      header.Filename,
		ContentType:   header.Header.Get("Content-Type"),
		SizeBytes:     header.Size,
		SHA256Hash:    hashHex,
		UploadedAt:    now,
		ExpiresAt:     expiresAt,
		MaxDownloads:  maxDownloads,
		DownloadCount: 0,
		ObjectKey:     objectKey,
		Metadata:      customMeta,
	}

	s.store.Add(metadata)

	// Update metrics
	uploadsTotal.WithLabelValues(s.config.TenantID, "success").Inc()
	uploadBytes.WithLabelValues(s.config.TenantID).Add(float64(header.Size))
	activePayloads.WithLabelValues(s.config.TenantID).Inc()

	// Generate signed download URL
	downloadURL := s.generateSignedURL(payloadID, expiresAt)

	// Return response
	response := map[string]interface{}{
		"payload_id":     payloadID,
		"filename":       header.Filename,
		"content_type":   header.Header.Get("Content-Type"),
		"size_bytes":     header.Size,
		"sha256_hash":    hashHex,
		"download_url":   downloadURL,
		"created_at":     now.Format(time.RFC3339),
		"expires_at":     expiresAt.Format(time.RFC3339),
		"max_downloads":  maxDownloads,
		"download_count": 0,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Payload uploaded: id=%s, file=%s, size=%d", payloadID, header.Filename, header.Size)
}

// handleDownload handles signed payload downloads
func (s *PayloadServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	// Extract payload ID from path
	path := strings.TrimPrefix(r.URL.Path, "/download/")
	payloadID := strings.Split(path, "/")[0]

	if payloadID == "" {
		downloadsTotal.WithLabelValues(s.config.TenantID, "invalid").Inc()
		http.Error(w, "Invalid payload ID", http.StatusBadRequest)
		return
	}

	// Verify signature
	expiresStr := r.URL.Query().Get("expires")
	signature := r.URL.Query().Get("sig")

	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		downloadsTotal.WithLabelValues(s.config.TenantID, "invalid").Inc()
		http.Error(w, "Invalid expiry", http.StatusBadRequest)
		return
	}

	if !s.verifySignedURL(payloadID, expires, signature) {
		downloadsTotal.WithLabelValues(s.config.TenantID, "unauthorized").Inc()
		http.Error(w, "Invalid signature", http.StatusForbidden)
		return
	}

	// Check expiry
	if time.Now().Unix() > expires {
		downloadsTotal.WithLabelValues(s.config.TenantID, "expired").Inc()
		http.Error(w, "URL expired", http.StatusGone)
		return
	}

	// Get metadata
	metadata, ok := s.store.Get(payloadID)
	if !ok {
		downloadsTotal.WithLabelValues(s.config.TenantID, "not_found").Inc()
		http.Error(w, "Payload not found", http.StatusNotFound)
		return
	}

	// Check download limit
	if metadata.MaxDownloads > 0 && metadata.DownloadCount >= metadata.MaxDownloads {
		downloadsTotal.WithLabelValues(s.config.TenantID, "limit_exceeded").Inc()
		http.Error(w, "Download limit exceeded", http.StatusGone)
		return
	}

	// Get object from MinIO
	ctx := r.Context()
	object, err := s.minioClient.GetObject(ctx, s.config.MinioBucket, metadata.ObjectKey, minio.GetObjectOptions{})
	if err != nil {
		downloadsTotal.WithLabelValues(s.config.TenantID, "error").Inc()
		log.Printf("MinIO get failed: %v", err)
		http.Error(w, "Storage error", http.StatusInternalServerError)
		return
	}
	defer object.Close()

	// Increment download counter
	count := s.store.IncrementDownloads(payloadID)

	// Set headers
	w.Header().Set("Content-Type", metadata.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", metadata.Filename))
	w.Header().Set("Content-Length", strconv.FormatInt(metadata.SizeBytes, 10))
	w.Header().Set("X-Content-SHA256", metadata.SHA256Hash)
	w.Header().Set("X-Download-Count", strconv.Itoa(count))

	// Stream file
	written, err := io.Copy(w, object)
	if err != nil {
		log.Printf("Download stream failed: %v", err)
		return
	}

	// Update metrics
	downloadsTotal.WithLabelValues(s.config.TenantID, "success").Inc()
	downloadBytes.WithLabelValues(s.config.TenantID).Add(float64(written))

	log.Printf("Payload downloaded: id=%s, file=%s, count=%d", payloadID, metadata.Filename, count)
}

// handleList returns list of payloads for the tenant
func (s *PayloadServer) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	payloads := s.store.List(s.config.TenantID)

	response := map[string]interface{}{
		"tenant_id": s.config.TenantID,
		"count":     len(payloads),
		"payloads":  payloads,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGet returns metadata for a specific payload
func (s *PayloadServer) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/payloads/")
	payloadID := strings.Split(path, "/")[0]

	metadata, ok := s.store.Get(payloadID)
	if !ok {
		http.Error(w, "Payload not found", http.StatusNotFound)
		return
	}

	// Include signed download URL
	response := map[string]interface{}{
		"payload_id":     metadata.PayloadID,
		"filename":       metadata.Filename,
		"content_type":   metadata.ContentType,
		"size_bytes":     metadata.SizeBytes,
		"sha256_hash":    metadata.SHA256Hash,
		"download_url":   s.generateSignedURL(metadata.PayloadID, metadata.ExpiresAt),
		"created_at":     metadata.UploadedAt.Format(time.RFC3339),
		"expires_at":     metadata.ExpiresAt.Format(time.RFC3339),
		"max_downloads":  metadata.MaxDownloads,
		"download_count": metadata.DownloadCount,
		"metadata":       metadata.Metadata,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleDelete removes a payload
func (s *PayloadServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/payloads/")
	payloadID := strings.Split(path, "/")[0]

	metadata, ok := s.store.Get(payloadID)
	if !ok {
		http.Error(w, "Payload not found", http.StatusNotFound)
		return
	}

	// Delete from MinIO
	ctx := r.Context()
	err := s.minioClient.RemoveObject(ctx, s.config.MinioBucket, metadata.ObjectKey, minio.RemoveObjectOptions{})
	if err != nil {
		log.Printf("MinIO delete failed: %v", err)
		http.Error(w, "Storage error", http.StatusInternalServerError)
		return
	}

	// Remove from store
	s.store.Delete(payloadID)
	activePayloads.WithLabelValues(s.config.TenantID).Dec()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "deleted",
		"payload_id": payloadID,
	})

	log.Printf("Payload deleted: id=%s", payloadID)
}

// handleHealth returns health status
func (s *PayloadServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check MinIO connectivity
	_, err := s.minioClient.BucketExists(ctx, s.config.MinioBucket)

	status := "healthy"
	code := http.StatusOK
	if err != nil {
		status = "unhealthy"
		code = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"status":    status,
		"tenant_id": s.config.TenantID,
	})
}

// handleReady returns readiness status
func (s *PayloadServer) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check MinIO connectivity
	exists, err := s.minioClient.BucketExists(ctx, s.config.MinioBucket)
	if err != nil || !exists {
		http.Error(w, "Not ready", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ready",
	})
}

// cleanupExpired removes expired payloads
func (s *PayloadServer) cleanupExpired(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.store.mu.Lock()
			now := time.Now()
			for id, p := range s.store.payloads {
				if now.After(p.ExpiresAt) {
					// Delete from MinIO
					err := s.minioClient.RemoveObject(ctx, s.config.MinioBucket, p.ObjectKey, minio.RemoveObjectOptions{})
					if err != nil {
						log.Printf("Failed to delete expired payload %s: %v", id, err)
						continue
					}
					delete(s.store.payloads, id)
					activePayloads.WithLabelValues(s.config.TenantID).Dec()
					log.Printf("Expired payload deleted: id=%s", id)
				}
			}
			s.store.mu.Unlock()
		}
	}
}

func main() {
	log.Println("Starting Mirqab Payload Server...")

	config := loadConfig()
	log.Printf("Configuration: tenant=%s, minio=%s, bucket=%s",
		config.TenantID, config.MinioEndpoint, config.MinioBucket)

	server, err := NewPayloadServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Ensure bucket exists
	ctx := context.Background()
	if err := server.ensureBucket(ctx); err != nil {
		log.Fatalf("Failed to ensure bucket: %v", err)
	}

	// Start cleanup goroutine
	go server.cleanupExpired(ctx)

	// Set up routes
	mux := http.NewServeMux()

	// Health endpoints (no auth)
	mux.HandleFunc("/health", server.handleHealth)
	mux.HandleFunc("/ready", server.handleReady)

	// Public download endpoint (signed URL auth)
	mux.HandleFunc("/download/", server.handleDownload)

	// Admin API (bearer token auth)
	mux.HandleFunc("/api/v1/payloads", server.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			server.handleList(w, r)
		case http.MethodPost:
			server.handleUpload(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/v1/payloads/", server.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			server.handleGet(w, r)
		case http.MethodDelete:
			server.handleDelete(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	// Start metrics server
	go func() {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		log.Printf("Metrics server listening on :%s", config.MetricsPort)
		if err := http.ListenAndServe(":"+config.MetricsPort, metricsMux); err != nil {
			log.Fatalf("Metrics server failed: %v", err)
		}
	}()

	// Start main server
	log.Printf("Payload server listening on %s", config.ListenAddr)
	if err := http.ListenAndServe(config.ListenAddr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
