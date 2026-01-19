// Mirqab Cloud Relay - Payload Server Unit Tests
package unit

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Payload Server Types (mirrored for testing)
// ============================================================================

// PayloadConfig for payload server testing
type PayloadConfig struct {
	TenantID           string
	AdminToken         string
	SigningSecret      string
	MaxPayloadSize     int64
	DefaultTTLHours    int
	MaxDownloadsPerURL int
}

// PayloadMetadata represents stored payload information
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
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// PayloadStore is an in-memory store for testing
type PayloadStore struct {
	mu       sync.RWMutex
	payloads map[string]*PayloadMetadata
}

// NewPayloadStore creates a new in-memory payload store
func NewPayloadStore() *PayloadStore {
	return &PayloadStore{
		payloads: make(map[string]*PayloadMetadata),
	}
}

// Add adds a payload to the store
func (s *PayloadStore) Add(p *PayloadMetadata) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payloads[p.PayloadID] = p
}

// Get retrieves a payload by ID
func (s *PayloadStore) Get(id string) (*PayloadMetadata, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.payloads[id]
	return p, ok
}

// Delete removes a payload
func (s *PayloadStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.payloads, id)
}

// IncrementDownloads atomically increments download count
func (s *PayloadStore) IncrementDownloads(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.payloads[id]; ok {
		p.DownloadCount++
		return p.DownloadCount
	}
	return 0
}

// List returns all payloads for a tenant
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

// Test configuration
var testPayloadConfig = &PayloadConfig{
	TenantID:           "test-tenant",
	AdminToken:         "test-admin-token",
	SigningSecret:      "test-signing-secret",
	MaxPayloadSize:     10 * 1024 * 1024, // 10MB
	DefaultTTLHours:    24,
	MaxDownloadsPerURL: 100,
}

// ============================================================================
// Tests
// ============================================================================

// TestPayloadStoreOperations tests the in-memory payload store
func TestPayloadStoreOperations(t *testing.T) {
	store := NewPayloadStore()

	// Test Add and Get
	t.Run("AddAndGet", func(t *testing.T) {
		payload := &PayloadMetadata{
			PayloadID:  "test-payload-1",
			TenantID:   "test-tenant",
			Filename:   "test.exe",
			SizeBytes:  1024,
			SHA256Hash: "abc123",
		}

		store.Add(payload)

		got, ok := store.Get("test-payload-1")
		require.True(t, ok, "Expected to find payload")
		assert.Equal(t, "test.exe", got.Filename)
	})

	// Test Get non-existent
	t.Run("GetNonExistent", func(t *testing.T) {
		_, ok := store.Get("non-existent")
		assert.False(t, ok, "Expected not to find non-existent payload")
	})

	// Test Delete
	t.Run("Delete", func(t *testing.T) {
		store.Delete("test-payload-1")
		_, ok := store.Get("test-payload-1")
		assert.False(t, ok, "Expected payload to be deleted")
	})

	// Test IncrementDownloads
	t.Run("IncrementDownloads", func(t *testing.T) {
		payload := &PayloadMetadata{
			PayloadID:     "test-payload-2",
			TenantID:      "test-tenant",
			DownloadCount: 0,
		}
		store.Add(payload)

		count := store.IncrementDownloads("test-payload-2")
		assert.Equal(t, 1, count)

		count = store.IncrementDownloads("test-payload-2")
		assert.Equal(t, 2, count)
	})

	// Test List
	t.Run("List", func(t *testing.T) {
		store2 := NewPayloadStore()

		store2.Add(&PayloadMetadata{PayloadID: "p1", TenantID: "tenant-a"})
		store2.Add(&PayloadMetadata{PayloadID: "p2", TenantID: "tenant-a"})
		store2.Add(&PayloadMetadata{PayloadID: "p3", TenantID: "tenant-b"})

		listA := store2.List("tenant-a")
		assert.Equal(t, 2, len(listA), "Expected 2 payloads for tenant-a")

		listB := store2.List("tenant-b")
		assert.Equal(t, 1, len(listB), "Expected 1 payload for tenant-b")
	})
}

// TestPayloadIDGeneration tests unique ID generation patterns
func TestPayloadIDGeneration(t *testing.T) {
	ids := make(map[string]bool)

	for i := 0; i < 1000; i++ {
		id := generateTestPayloadID()
		require.Equal(t, 32, len(id), "Expected ID length 32")
		require.False(t, ids[id], "Duplicate ID generated")
		ids[id] = true
	}
}

func generateTestPayloadID() string {
	b := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		// Fallback to time-based
		return fmt.Sprintf("%016x%016x", time.Now().UnixNano(), time.Now().UnixNano()+1)
	}
	return hex.EncodeToString(b)
}

// TestSignedURLGeneration tests URL signing and verification
func TestSignedURLGeneration(t *testing.T) {
	secret := testPayloadConfig.SigningSecret

	t.Run("GenerateAndVerify", func(t *testing.T) {
		payloadID := "test-payload-id"
		expiresAt := time.Now().Add(1 * time.Hour).Unix()

		// Generate signature
		message := fmt.Sprintf("%s:%d", payloadID, expiresAt)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(message))
		signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

		// Build URL
		url := fmt.Sprintf("/download/%s?expires=%d&sig=%s", payloadID, expiresAt, signature)
		assert.True(t, strings.HasPrefix(url, "/download/"+payloadID))

		// Verify signature
		valid := verifyTestSignature(secret, payloadID, expiresAt, signature)
		assert.True(t, valid, "Signature verification failed")
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		payloadID := "test-payload-id"
		expiresAt := time.Now().Add(1 * time.Hour).Unix()

		valid := verifyTestSignature(secret, payloadID, expiresAt, "invalid-signature")
		assert.False(t, valid, "Expected invalid signature to fail verification")
	})

	t.Run("TamperedPayloadID", func(t *testing.T) {
		originalID := "original-id"
		expiresAt := time.Now().Add(1 * time.Hour).Unix()

		// Generate signature for original ID
		message := fmt.Sprintf("%s:%d", originalID, expiresAt)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(message))
		signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

		// Try to verify with different payload ID
		valid := verifyTestSignature(secret, "tampered-id", expiresAt, signature)
		assert.False(t, valid, "Expected tampered payload ID to fail verification")
	})
}

func verifyTestSignature(secret, payloadID string, expiresAt int64, providedSig string) bool {
	message := fmt.Sprintf("%s:%d", payloadID, expiresAt)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedSig := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expectedSig), []byte(providedSig))
}

// TestPayloadAuthMiddleware tests authentication middleware
func TestPayloadAuthMiddleware(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Check auth header
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		if token != testPayloadConfig.AdminToken {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}

	t.Run("ValidToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+testPayloadConfig.AdminToken)
		rr := httptest.NewRecorder()

		handler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		rr := httptest.NewRecorder()

		handler(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("MissingToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

// TestPayloadHealthEndpoint tests health check pattern
func TestPayloadHealthEndpoint(t *testing.T) {
	t.Run("HealthEndpointExists", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"service": "payload-server",
			})
		}

		req := httptest.NewRequest("GET", "/health", nil)
		rr := httptest.NewRecorder()

		handler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "healthy", response["status"])
	})
}

// TestPayloadSHA256Hashing tests file hash computation
func TestPayloadSHA256Hashing(t *testing.T) {
	content := []byte("test content for hashing")
	hash := sha256.Sum256(content)
	hashHex := hex.EncodeToString(hash[:])

	assert.Equal(t, 64, len(hashHex), "Expected hash length 64")

	// Verify consistent hashing
	hash2 := sha256.Sum256(content)
	hashHex2 := hex.EncodeToString(hash2[:])
	assert.Equal(t, hashHex, hashHex2, "Hash should be deterministic")
}

// TestPayloadHMACSignature tests HMAC signature generation
func TestPayloadHMACSignature(t *testing.T) {
	secret := "test-secret"
	message := "test-message"

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	// Verify deterministic
	mac2 := hmac.New(sha256.New, []byte(secret))
	mac2.Write([]byte(message))
	signature2 := base64.URLEncoding.EncodeToString(mac2.Sum(nil))

	assert.Equal(t, signature, signature2, "HMAC signature should be deterministic")

	// Verify different message produces different signature
	mac3 := hmac.New(sha256.New, []byte(secret))
	mac3.Write([]byte("different-message"))
	signature3 := base64.URLEncoding.EncodeToString(mac3.Sum(nil))

	assert.NotEqual(t, signature, signature3, "Different messages should produce different signatures")
}

// TestPayloadMetadataJSON tests JSON serialization
func TestPayloadMetadataJSON(t *testing.T) {
	now := time.Now()
	metadata := &PayloadMetadata{
		PayloadID:     "test-id",
		TenantID:      "test-tenant",
		Filename:      "payload.exe",
		ContentType:   "application/octet-stream",
		SizeBytes:     12345,
		SHA256Hash:    "abcdef123456",
		UploadedAt:    now,
		ExpiresAt:     now.Add(24 * time.Hour),
		MaxDownloads:  100,
		DownloadCount: 5,
		ObjectKey:     "test-tenant/test-id/payload.exe",
		Metadata:      map[string]string{"campaign": "test"},
	}

	// Serialize
	jsonData, err := json.Marshal(metadata)
	require.NoError(t, err, "Failed to marshal")

	// Deserialize
	var decoded PayloadMetadata
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err, "Failed to unmarshal")

	// Verify fields
	assert.Equal(t, metadata.PayloadID, decoded.PayloadID)
	assert.Equal(t, metadata.Filename, decoded.Filename)
	assert.Equal(t, metadata.SizeBytes, decoded.SizeBytes)
	assert.Equal(t, "test", decoded.Metadata["campaign"])
}

// TestPayloadMultipartFormParsing tests file upload parsing
func TestPayloadMultipartFormParsing(t *testing.T) {
	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file
	part, err := writer.CreateFormFile("file", "test.txt")
	require.NoError(t, err)
	part.Write([]byte("test file content"))

	// Add metadata
	writer.WriteField("sha256_hash", "")
	writer.WriteField("expires_hours", "48")
	writer.WriteField("max_downloads", "50")
	writer.WriteField("metadata", `{"key": "value"}`)

	writer.Close()

	// Parse
	req := httptest.NewRequest("POST", "/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	err = req.ParseMultipartForm(10 * 1024 * 1024)
	require.NoError(t, err, "Failed to parse multipart form")

	file, header, err := req.FormFile("file")
	require.NoError(t, err, "Failed to get file")
	defer file.Close()

	assert.Equal(t, "test.txt", header.Filename)

	content, _ := io.ReadAll(file)
	assert.Equal(t, "test file content", string(content))
	assert.Equal(t, "48", req.FormValue("expires_hours"))
}

// TestPayloadDownloadLimitEnforcement tests download counting
func TestPayloadDownloadLimitEnforcement(t *testing.T) {
	store := NewPayloadStore()

	payload := &PayloadMetadata{
		PayloadID:     "limited-payload",
		TenantID:      "test-tenant",
		MaxDownloads:  3,
		DownloadCount: 0,
	}
	store.Add(payload)

	// Simulate downloads
	for i := 1; i <= 5; i++ {
		count := store.IncrementDownloads("limited-payload")

		p, _ := store.Get("limited-payload")
		if i <= 3 {
			assert.Equal(t, i, count, "Expected count %d, got %d", i, count)
		}

		// Check if limit exceeded
		if p.DownloadCount > p.MaxDownloads {
			if i <= 3 {
				t.Errorf("Limit should not be exceeded at download %d", i)
			}
		}
	}

	// Verify final count
	p, _ := store.Get("limited-payload")
	assert.Equal(t, 5, p.DownloadCount)
}

// TestPayloadExpiryCheck tests TTL expiration
func TestPayloadExpiryCheck(t *testing.T) {
	t.Run("NotExpired", func(t *testing.T) {
		expiresAt := time.Now().Add(1 * time.Hour)
		assert.False(t, time.Now().After(expiresAt), "Should not be expired")
	})

	t.Run("Expired", func(t *testing.T) {
		expiresAt := time.Now().Add(-1 * time.Hour)
		assert.True(t, time.Now().After(expiresAt), "Should be expired")
	})
}

// TestPayloadObjectKeyGeneration tests storage path generation
func TestPayloadObjectKeyGeneration(t *testing.T) {
	tenantID := "tenant-abc123"
	payloadID := "payload-xyz789"
	filename := "malware.exe"

	objectKey := fmt.Sprintf("%s/%s/%s", tenantID, payloadID, filename)

	expected := "tenant-abc123/payload-xyz789/malware.exe"
	assert.Equal(t, expected, objectKey)

	// Verify path components can be extracted
	parts := strings.Split(objectKey, "/")
	assert.Equal(t, 3, len(parts), "Expected 3 path components")
	assert.Equal(t, tenantID, parts[0], "Tenant ID mismatch in path")
	assert.Equal(t, payloadID, parts[1], "Payload ID mismatch in path")
	assert.Equal(t, filename, parts[2], "Filename mismatch in path")
}

// TestPayloadStoreConcurrency tests concurrent access to store
func TestPayloadStoreConcurrency(t *testing.T) {
	store := NewPayloadStore()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			store.Add(&PayloadMetadata{
				PayloadID: fmt.Sprintf("payload-%d", id),
				TenantID:  "test-tenant",
			})
		}(i)
	}
	wg.Wait()

	// Verify all payloads were added
	list := store.List("test-tenant")
	assert.Equal(t, 100, len(list))

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			store.Get(fmt.Sprintf("payload-%d", id))
		}(i)
	}
	wg.Wait()
}

// BenchmarkPayloadStoreAdd benchmarks store operations
func BenchmarkPayloadStoreAdd(b *testing.B) {
	store := NewPayloadStore()

	for i := 0; i < b.N; i++ {
		store.Add(&PayloadMetadata{
			PayloadID: fmt.Sprintf("payload-%d", i),
			TenantID:  "test-tenant",
		})
	}
}

func BenchmarkPayloadStoreGet(b *testing.B) {
	store := NewPayloadStore()

	// Pre-populate
	for i := 0; i < 1000; i++ {
		store.Add(&PayloadMetadata{
			PayloadID: fmt.Sprintf("payload-%d", i),
			TenantID:  "test-tenant",
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Get(fmt.Sprintf("payload-%d", i%1000))
	}
}
