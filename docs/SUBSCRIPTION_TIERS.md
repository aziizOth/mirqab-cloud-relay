# Mirqab Cloud Relay - Subscription Tiers

## Overview

Mirqab Cloud Relay offers tiered subscription plans to accommodate organizations of all sizes, from initial evaluation to enterprise-scale adversary simulation operations.

---

## Tier Comparison

| Feature | Trial | POC | Starter | Professional | Enterprise |
|---------|-------|-----|---------|--------------|------------|
| **Validity Period** | 14 days | 6 months | 1 year | 1 year | 1 year |
| **C2 Channels** | 2 | 10 | 5 | 20 | 100 |
| **Payload Storage** | 1 GB | 25 GB | 10 GB | 50 GB | 500 GB |
| **HTTP/S Beacon** | Yes | Yes | Yes | Yes | Yes |
| **DNS Tunneling** | - | Yes | Yes | Yes | Yes |
| **SMB Lateral Movement** | - | - | - | Yes | Yes |
| **Custom Protocols** | - | - | - | - | Yes |
| **Payload Hosting** | - | Yes | Yes | Yes | Yes |
| **Basic Reporting** | Yes | - | Yes | - | - |
| **Advanced Reporting** | - | Yes | - | Yes | Yes |
| **Custom Domains** | - | - | - | Yes | Yes |
| **API Access** | - | Yes | - | Yes | Yes |
| **SSO Integration** | - | - | - | - | Yes |
| **Dedicated Support** | - | POC Support | - | - | Yes |
| **SLA** | - | - | - | - | 99.9% |

---

## What is a C2 Channel?

A **C2 (Command & Control) Channel** is a dedicated communication pathway between the simulated adversary infrastructure (Cloud Relay) and beacon implants deployed during security exercises.

### Channel Types

| Type | Description | Use Case |
|------|-------------|----------|
| **HTTP/S** | HTTPS-based beacon with configurable intervals and jitter | Standard web traffic simulation, proxy-aware environments |
| **DNS** | DNS tunneling via A/TXT/CNAME records | Restricted networks where only DNS is allowed |
| **SMB** | SMB-based lateral movement simulation | Internal network pivot simulation |
| **Custom** | User-defined protocol handlers | Advanced APT simulation, custom malware profiles |

### Channel Limits by Tier

- **Trial (2 channels)**: Sufficient for basic HTTP beacon testing
- **POC (10 channels)**: Run multiple concurrent simulations across different protocols
- **Starter (5 channels)**: Small team operations with HTTP and DNS
- **Professional (20 channels)**: Full red team operations with multiple simultaneous campaigns
- **Enterprise (100 channels)**: Large-scale, multi-team adversary simulation programs

### What Counts as a Channel?

Each unique combination of:
- Protocol type (HTTP, DNS, SMB)
- Endpoint configuration (domain, port, profile)
- Tenant isolation boundary

For example, if you need:
- 1 HTTP beacon for external phishing simulation
- 1 DNS tunnel for exfiltration testing
- 1 HTTP beacon for a different campaign

That would consume **3 channels**.

---

## What is Payload Storage?

**Payload Storage** is secure cloud storage for hosting files that simulated implants can download during security exercises.

### Use Cases

| Scenario | Description |
|----------|-------------|
| **Staged Payloads** | Host secondary payloads for multi-stage attack simulation |
| **Tool Delivery** | Serve legitimate red team tools (Mimikatz, Rubeus, etc.) |
| **Exfiltration Targets** | Store test data files for exfiltration exercises |
| **Dropper Hosting** | Host initial access payloads for phishing simulations |

### Storage Features

- **Secure Upload**: mTLS-authenticated uploads from Master Server
- **Signed URLs**: Time-limited, cryptographically signed download URLs
- **Download Limits**: Configure maximum download count per payload
- **Auto-Expiry**: Payloads automatically deleted after configurable TTL
- **Hash Verification**: SHA-256 verification for integrity checking

### Storage Limits by Tier

| Tier | Storage | Typical Use |
|------|---------|-------------|
| **Trial** | 1 GB | Basic tool hosting |
| **POC** | 25 GB | Full POC with multiple payloads |
| **Starter** | 10 GB | Small team operations |
| **Professional** | 50 GB | Multiple concurrent campaigns |
| **Enterprise** | 500 GB | Large-scale operations, historical archives |

---

## Tier Details

### Trial (14 Days)

**Purpose**: Quick evaluation of Cloud Relay capabilities

**Ideal For**:
- Initial platform evaluation
- Technical proof of concept
- Demo environments

**Includes**:
- 2 C2 channels (HTTP only)
- 1 GB payload storage
- Basic reporting dashboard
- Self-service documentation

**Limitations**:
- No DNS tunneling
- No API access
- No dedicated support

---

### POC (6 Months)

**Purpose**: Extended proof of concept for serious evaluators

**Ideal For**:
- Pre-purchase validation
- Pilot programs
- Security team training

**Includes**:
- 10 C2 channels (HTTP + DNS)
- 25 GB payload storage
- Advanced reporting with MITRE ATT&CK mapping
- Full API access for integration testing
- Dedicated POC support contact
- Payload hosting with signed URLs

**Why 6 Months?**
- Sufficient time to run multiple exercise cycles
- Allows integration with existing security tools
- Enables thorough evaluation across different scenarios
- Time to demonstrate ROI to stakeholders

---

### Starter (1 Year)

**Purpose**: Entry-level production subscription

**Ideal For**:
- Small security teams (2-5 members)
- Organizations starting adversary simulation programs
- Compliance-driven testing requirements

**Includes**:
- 5 C2 channels (HTTP + DNS)
- 10 GB payload storage
- Payload hosting
- Basic reporting
- Email support

---

### Professional (1 Year)

**Purpose**: Full-featured production subscription

**Ideal For**:
- Mid-size security teams (5-15 members)
- Active red team programs
- Regular penetration testing operations

**Includes**:
- 20 C2 channels (HTTP + DNS + SMB)
- 50 GB payload storage
- Advanced reporting with MITRE ATT&CK mapping
- Custom domain support (bring your own domains)
- Full API access
- Priority email support

**Key Features**:
- SMB lateral movement simulation
- Custom domain integration for realistic phishing
- API for CI/CD integration
- Advanced analytics dashboard

---

### Enterprise (1 Year)

**Purpose**: Unlimited scale for large organizations

**Ideal For**:
- Large security organizations (15+ members)
- Multi-team operations
- Managed security service providers (MSSPs)
- Organizations with strict compliance requirements

**Includes**:
- 100 C2 channels (all protocols + custom)
- 500 GB payload storage
- All features from Professional tier
- Custom protocol development
- SSO integration (SAML/OIDC)
- Dedicated support engineer
- 99.9% SLA guarantee
- Quarterly business reviews

**Enterprise-Only Features**:
- Custom C2 protocol handlers
- SSO with your identity provider
- Dedicated infrastructure options
- Custom SLA terms available

---

## License Key Format

All tiers use the same secure license key format:

```
MIRQAB-{TIER}-{CHECKSUM}-{RANDOM}
```

**Examples**:
- Trial: `MIRQAB-TRL-A1B2C3D4-E5F6G7H8I9J0`
- POC: `MIRQAB-POC-B2C3D4E5-F6G7H8I9J0K1`
- Starter: `MIRQAB-STR-C3D4E5F6-G7H8I9J0K1L2`
- Professional: `MIRQAB-PRO-D4E5F6G7-H8I9J0K1L2M3`
- Enterprise: `MIRQAB-ENT-E5F6G7H8-I9J0K1L2M3N4`

**Security Features**:
- HMAC-SHA256 checksum for tamper detection
- Cryptographically random suffix
- Tier encoded in key for quick validation
- Server-side validation required for activation

---

## Upgrade Path

```
Trial (14 days)
    │
    ├──► POC (6 months) ──► Professional or Enterprise
    │
    └──► Starter (1 year) ──► Professional ──► Enterprise
```

**Upgrade Process**:
1. Contact Mirqab sales or use Command Center
2. Receive new license key for upgraded tier
3. Apply new license in Master Server settings
4. Existing data and configurations preserved
5. New limits effective immediately

---

## Frequently Asked Questions

### Can I exceed my channel limit temporarily?

No. Channel limits are hard limits. If you need more capacity, upgrade to a higher tier or contact sales for custom arrangements.

### What happens when my subscription expires?

- 7 days before expiry: Warning notifications
- On expiry: New operations blocked, existing data preserved
- 30 days after expiry: Data export available
- 60 days after expiry: Tenant data deleted

### Can I downgrade my subscription?

Yes, at renewal time. Downgrade will take effect at the start of the next billing period. Ensure your usage fits within the new tier limits.

### Is there a free tier?

The 14-day Trial tier is free and requires no payment information. For extended evaluation, request a POC license from sales.

### Can I get a custom tier?

Enterprise customers can negotiate custom terms including:
- Custom channel limits
- Custom storage quotas
- On-premises deployment options
- Custom SLA terms

Contact enterprise@mirqab.io for custom arrangements.

---

## Contact

- **Sales**: sales@mirqab.io
- **Enterprise**: enterprise@mirqab.io
- **Support**: support@mirqab.io
- **POC Requests**: poc@mirqab.io
