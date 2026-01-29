# Competitive Analysis — Attack Simulation Platforms

Comprehensive comparison of open-source attack simulation tools against the Mirqab OffenSight platform. Analysis conducted January 2026.

---

## Tools Evaluated

| Tool | Source | Purpose |
|------|--------|---------|
| **MITRE Caldera** | mitre/caldera | Adversary emulation with fact-based adaptive planning |
| **Atomic Red Team** | redcanaryco/atomic-red-team | 2,296 atomic tests across 328 ATT&CK techniques |
| **OpenAEV** | Filigran (openaev.io) | Exercise/scenario management with inject dependency chains |
| **PentestGPT** | USENIX Security 2024 | AI-autonomous pentesting agent (86.5% benchmark success) |
| **Stratus Red Team** | DataDog/stratus-red-team | 73 cloud-native attack techniques (AWS/Azure/GCP/K8s) |
| **VECTR** | SecurityRiskAdvisors/VECTR | Purple team campaign tracking & resilience trending |
| **Adversary Emulation Library** | MITRE CTID | 11 APT emulation plans (APT29, Sandworm, FIN7, etc.) |
| **Infection Monkey** | guardicore/monkey | Self-propagating adversary simulation |
| **Metta** | uber-common/metta | Uber's ATT&CK simulation via Redis/Celery queue |
| **Sigma** | SigmaHQ/sigma | 3,095+ universal SIEM detection rules |
| **Chainsaw** | WithSecureLabs/chainsaw | Fast Windows forensic log analysis (Rust) |
| **ATT&CK Navigator** | mitre-attack/attack-navigator | ATT&CK coverage heatmap visualization |

---

## Mirqab OffenSight — Current Capabilities

| Capability | Detail |
|------------|--------|
| Attack library | 224 attacks, 109 MITRE ATT&CK techniques |
| Evidence correlation | Intelligent scoring (HIGH/MEDIUM/LOW confidence) |
| Gap analysis | Auto-generates Sigma rules + SIEM queries for missed attacks |
| Security control validation | Tests EDR, AV, WAF, SIEM, firewall effectiveness |
| Multi-tenant | SaaS-ready with tenant isolation |
| Tool distribution | On-demand Mandiant-style transfer (no pre-install) |
| Agent system | Master-agent polling with health monitoring |
| Execution models | 6 types (host-only, source-dest, inbound/outbound external, network actor, crucible) |
| Safety levels | 4 tiers (safe, controlled, restricted, dangerous) |

---

## Feature Comparison Matrix

| Feature | OffenSight | Caldera | ART | OpenAEV | Stratus | VECTR | Monkey |
|---------|:----------:|:-------:|:---:|:-------:|:-------:|:-----:|:------:|
| Attack library size | 224 | 500+ | 2,296 | Plugin | 73 | — | ~20 |
| ATT&CK techniques | 109 | 200+ | 328 | Plugin | 73 | — | ~15 |
| Evidence correlation | **Yes** | No | No | No | No | No | No |
| Gap analysis (Sigma) | **Yes** | No | No | No | No | No | No |
| Security control validation | **Yes** | No | No | Partial | No | Track | No |
| Multi-tenant | **Yes** | No | No | No | No | No | No |
| Fact-based planning | No | **Yes** | No | No | No | No | No |
| C2 channels | 1 (HTTP) | **9** | — | 1 | — | — | — |
| Cloud attacks | Partial | No | Partial | No | **73** | — | No |
| APT profiles | No | Partial | No | **Yes** | No | No | No |
| Campaign trending | No | No | No | Partial | No | **Yes** | No |
| Self-propagation | No | No | No | No | No | No | **Yes** |
| AI-assisted | No | No | No | No | No | No | No |
| Obfuscation engine | No | **Yes** | No | No | No | No | No |
| Expectation framework | Partial | No | No | **Yes** | No | No | No |
| Pause/resume | No | Yes | — | **Yes** | — | — | — |

**Legend:** **Yes** = best-in-class, Yes = has feature, Partial = limited, No = absent, — = not applicable

---

## What OffenSight Has That Others Don't

1. **Intelligent Evidence Correlation** — Scores each SIEM event by IP match (+40), username match (+20), Event ID match (+15), timestamp proximity (+10). Filters false positives before storing. No other tool does this.

2. **Automated Gap Analysis** — When an attack is missed by security controls, auto-generates a Sigma rule and SIEM query to close the gap. Unique to OffenSight.

3. **Security Control Validation** — Each attack definition specifies what EDR/AV/WAF/SIEM *should* do. The platform validates whether controls actually worked. Others just execute attacks.

4. **Multi-Tenant Architecture** — One platform serves multiple clients with full isolation. Caldera, OpenAEV, and all others are single-tenant.

5. **On-Demand Tool Distribution** — Tools transferred to agents at runtime, executed, then securely deleted. No pre-installation required. Caldera requires tools pre-installed on agents.

6. **Evidence Fingerprints** — Each attack defines REMOTE vs LOCAL correlation strategy with expected Windows Event IDs and correlation windows. Enables precise evidence matching.

---

## Adoptable Ideas — Ranked by Impact

### P0 — Critical (Next Sprint)

#### 1. APT Adversary Profiles
**Source:** Adversary Emulation Library (CTID)
**What:** Pre-built attack chains emulating real APT groups (APT29, Sandworm, FIN7, Wizard Spider). Each plan chains 10-30 techniques in realistic order with tool-specific procedures.
**Adopt:** Create "Adversary Profiles" that chain existing OffenSight attacks into APT campaigns. Start with APT29 (espionage) and Wizard Spider (ransomware). Map to existing 224 attacks.

#### 2. Expectation Framework
**Source:** OpenAEV
**What:** 7 expectation types with 0-100 scoring: Detection (SIEM alerted), Prevention (EDR blocked), Vulnerability (vuln exists), Challenge (CTF flag), Manual (operator validates). Supports partial credit.
**Adopt:** Formalize `security_control_spec` into scored expectations. "EDR should block within 5s" = Prevention expectation. "SIEM should alert within 5m" = Detection expectation. Score each: SUCCESS (100), PARTIAL (50), FAILED (0).

#### 3. Campaign Trending & Resilience Tracking
**Source:** VECTR
**What:** Track purple team campaigns over time. Show detection rate improvements across repeated assessments. ATT&CK heatmaps with sub-technique granularity.
**Adopt:** Add campaign history to OffenSight. After each assessment run, store results. Show trending: "T1003.006 DCSync: Detected 0/3 in Jan → 2/3 in Feb → 3/3 in Mar." Heatmap showing red (missed) → green (detected) evolution.

### P1 — High Priority

#### 4. Fact-Based Adaptive Planning
**Source:** MITRE Caldera
**What:** Knowledge graph tracks discovered facts (users, IPs, hashes, services). Attacks dynamically generate variants based on facts. Discover 10 domain users → Kerberoasting runs 10 times. Relationships enable reasoning: "user A is member_of Domain Admins."
**Adopt:** Add fact extraction to attack output parsing. After DCSync succeeds, extract hashes as facts. Feed into Pass-the-Hash attack automatically. Build dependency graph between attacks.

#### 5. Atomic Red Team Import Layer
**Source:** Atomic Red Team
**What:** 2,296 tests in standardized YAML with input arguments, prerequisites, cleanup commands. Covers 328 techniques vs OffenSight's 109.
**Adopt:** Build an ART YAML → OffenSight JSON converter. Import ART tests as "lightweight" attacks (no evidence correlation). Your 224 attacks remain "deep" (with evidence + gap analysis). Combined: 2,500+ attacks.

#### 6. Cloud Attack Library
**Source:** Stratus Red Team
**What:** 73 idempotent cloud attacks: AWS (49), GCP (9), Azure (4), K8s (7). Three-phase model: warm-up (provision infra) → detonate (execute attack) → cleanup (destroy infra). Each technique includes detection guidance.
**Adopt:** Import cloud techniques into Cloud Relay. Add `execution_model_type: cloud_native` for attacks that run against cloud APIs (S3 bucket exposure, IAM privilege escalation, CloudTrail tampering).

#### 7. Command Obfuscation Engine
**Source:** MITRE Caldera
**What:** Pluggable obfuscation: plain-text, base64, custom modules. Commands obfuscated per-agent per-platform. PowerShell UTF-16LE base64, bash eval+decode.
**Adopt:** Add obfuscation variants to existing attacks. Run each attack twice: once plain, once obfuscated. Compare detection rates. Key differentiator for gap analysis: "Your EDR detects plain Mimikatz but misses base64-encoded variant."

### P2 — Medium Priority

#### 8. Multi-Protocol C2 Channels
**Source:** MITRE Caldera
**What:** 9 C2 protocols (HTTP, DNS, TCP, UDP, WebSocket, Slack, GitHub Gist, FTP). Agents can switch protocols mid-operation. DNS tunneling via TXT/A/AAAA records.
**Adopt:** Cloud Relay currently has HTTP C2 only. Add DNS tunneling (T1071.004) and WebSocket channels. Test whether network controls detect each protocol.

#### 9. Self-Propagation Mode
**Source:** Infection Monkey
**What:** Agent discovers adjacent hosts, attempts exploitation (Log4Shell, SMB, SSH, RDP, WMI), and auto-deploys to new targets using harvested credentials.
**Adopt:** After credential dump succeeds, auto-deploy OffenSight agent to discovered targets. Validates network segmentation and lateral movement detection.

#### 10. AI-Assisted Attack Mode
**Source:** PentestGPT
**What:** Autonomous agent with exhaustive fallback strategies. When technique fails, tries alternatives (different shells, ports, encodings). Pause/resume/inject pattern for human oversight. Real-time objective detection via regex.
**Adopt:** When an attack fails, suggest alternative techniques from the library. "DCSync blocked? Try Kerberoasting (T1558.003) or NTDS.dit copy (T1003.003)." Implement operator injection for manual overrides during autonomous scenarios.

#### 11. Sigma Rule Pre-Validation
**Source:** SigmaHQ
**What:** 3,095+ detection rules mapped to ATT&CK techniques.
**Adopt:** For each of your 224 attacks, check if a matching Sigma rule exists in the SigmaHQ repo. Flag techniques with zero detection rules. Pre-load relevant Sigma rules per attack for comparison against customer SIEM.

### P3 — Nice to Have

#### 12. Exercise Pause/Resume with Duration Compensation
**Source:** OpenAEV
**What:** Pause mid-exercise, automatically adjust all future inject schedules on resume. Tracks pause duration and shifts timelines.
**Adopt:** Add scenario pause/resume. Queue remaining attacks and adjust timing on resume.

---

## Architecture Comparison

### MITRE Caldera
- **Language:** Python (aiohttp)
- **Storage:** In-memory (loses state on restart)
- **Agent:** Sandcat (Go), Manx (reverse shell)
- **Planning:** Pluggable Python planners with state machines
- **Strength:** Fact-based intelligence, 9 C2 protocols, plugin ecosystem
- **Weakness:** No persistent storage, no evidence correlation, single-tenant

### OpenAEV
- **Language:** Java (Spring Boot 3.3.7, Java 21)
- **Storage:** PostgreSQL + Elasticsearch + MinIO + RabbitMQ
- **Agents:** Caldera integration, CrowdStrike RTR, Tanium
- **Planning:** Inject dependency chains with duration offsets
- **Strength:** Exercise management, expectation scoring, multi-executor, OpenCTI integration
- **Weakness:** Heavy stack, no native evidence correlation, academic focus

### Atomic Red Team
- **Language:** YAML definitions (no runtime)
- **Execution:** PowerShell (34%), cmd (33%), sh (24%), bash (8%), manual (1%)
- **Strength:** Largest technique coverage (328), community contributions, simple schema
- **Weakness:** No orchestration, no evidence collection, no centralized management

### PentestGPT
- **Language:** Python + Claude Code SDK
- **Architecture:** Autonomous agent with EventBus pub/sub
- **Strength:** 86.5% success rate, $0.42 median cost, fully autonomous
- **Weakness:** No custom tools, single-target focus, cost-per-run model

### Stratus Red Team
- **Language:** Go binary
- **Architecture:** Terraform-provisioned infrastructure, idempotent phases
- **Strength:** Only tool focused on cloud-native attacks, 73 techniques
- **Weakness:** Cloud-only, no on-prem support

---

## Coverage Gap Analysis

### Techniques OffenSight Covers That Others Miss
- Container escape (T1611) with Crucible isolation
- WAF testing via Cloud Relay (T1190 with real traffic)
- Network actor service exposure (SMB/RDP/SSH on-demand)
- Evidence-correlated credential access (T1003.001-008)

### Techniques Others Cover That OffenSight Should Add
- **Cloud attacks** (Stratus): S3 bucket exposure, IAM escalation, CloudTrail tampering
- **Wireless** (none currently): Rogue AP, deauth, WPA cracking
- **Mobile** (none currently): Android/iOS attack vectors
- **ICS/OT** (Caldera OT plugin): SCADA/PLC attacks
- **Social engineering** (OpenAEV): SMS, Mastodon, voice calls

---

## Conclusion

Mirqab OffenSight's **evidence correlation, gap analysis, and security control validation** are unique differentiators that no competitor offers. The platform should focus on:

1. **Breadth** — Import ART's 2,296 tests + Stratus's 73 cloud attacks
2. **Depth** — Add expectation scoring + campaign trending from OpenAEV/VECTR
3. **Intelligence** — Adopt Caldera's fact-based planning for adaptive attack chains
4. **Profiles** — Build APT campaign profiles from CTID's emulation library

Combined, these additions would create the most comprehensive security validation platform available — open-source or commercial.
