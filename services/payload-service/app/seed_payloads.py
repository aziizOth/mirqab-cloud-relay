"""Seed pre-built payloads for security testing."""
import hashlib
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from .models import Payload, PayloadCategory, SafetyLevel
from .config import settings

# EICAR Standard Test String - universally detected by AV
# This is the official EICAR test file string, NOT malware
# Reference: https://www.eicar.org/download-anti-malware-testfile/
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Payload definitions to seed
SEED_PAYLOADS = [
    # === EXECUTABLES ===
    {
        "name": "EICAR Test File (COM)",
        "filename": "eicar.com",
        "category": PayloadCategory.EXECUTABLE,
        "subcategory": "eicar",
        "content": EICAR_STRING.encode('ascii'),
        "mime_type": "application/x-dosexec",
        "description": "Standard EICAR antivirus test file. Should be detected by all AV solutions.",
        "mitre_technique_id": "T1204.002",
        "expected_detection": "av",
        "safety_level": SafetyLevel.SAFE,
        "endpoint": "download",
    },
    {
        "name": "EICAR Test File (EXE)",
        "filename": "eicar.exe",
        "category": PayloadCategory.EXECUTABLE,
        "subcategory": "eicar",
        # EICAR with minimal MZ header to look like executable
        "content": EICAR_STRING.encode('ascii'),
        "mime_type": "application/x-dosexec",
        "description": "EICAR test file with .exe extension. Tests AV detection by extension.",
        "mitre_technique_id": "T1204.002",
        "expected_detection": "av",
        "safety_level": SafetyLevel.SAFE,
        "endpoint": "download",
    },
    {
        "name": "Generic Malware Payload",
        "filename": "payload.exe",
        "category": PayloadCategory.EXECUTABLE,
        "subcategory": "eicar",
        "content": EICAR_STRING.encode('ascii'),
        "mime_type": "application/x-dosexec",
        "description": "Generic payload file containing EICAR test string.",
        "mitre_technique_id": "T1204.002",
        "expected_detection": "av",
        "safety_level": SafetyLevel.SAFE,
        "endpoint": "download",
    },
    {
        "name": "Trojan Generic",
        "filename": "trojan-generic.exe",
        "category": PayloadCategory.EXECUTABLE,
        "subcategory": "eicar",
        "content": EICAR_STRING.encode('ascii'),
        "mime_type": "application/x-dosexec",
        "description": "Generic trojan test file. Should be detected by AV.",
        "mitre_technique_id": "T1204.002",
        "expected_detection": "av",
        "safety_level": SafetyLevel.SAFE,
        "endpoint": "download",
    },

    # === SCRIPTS ===
    {
        "name": "PowerShell Download Cradle",
        "filename": "script.ps1",
        "category": PayloadCategory.SCRIPT,
        "subcategory": "powershell",
        "content": b"""# EICAR Test - PowerShell Download Cradle
# This script contains the EICAR test string for AV detection testing
$testString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
Write-Host "EICAR Test String Executed"
# Typical download cradle pattern (harmless - connects to localhost)
# IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/test')
""",
        "mime_type": "application/x-powershell",
        "description": "PowerShell download cradle template. Tests proxy/EDR detection.",
        "mitre_technique_id": "T1059.001",
        "expected_detection": "edr,proxy",
        "safety_level": SafetyLevel.SAFE,
        "endpoint": "stage",
    },
    {
        "name": "Invoke-Mimikatz Signature",
        "filename": "invoke-mimikatz.ps1",
        "category": PayloadCategory.SCRIPT,
        "subcategory": "powershell",
        "content": b"""# EICAR Test - Mimikatz Signature File
# This file contains strings that should trigger AMSI/EDR detection
# NO actual Mimikatz functionality - just detection strings

$EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Mimikatz-like function names (non-functional)
function Invoke-Mimikatz {
    Write-Host "This is a test file, not real Mimikatz"
    Write-Host $EICAR
}

# Common Mimikatz strings that trigger detection
$testStrings = @(
    "sekurlsa::logonpasswords",
    "lsadump::sam",
    "privilege::debug"
)

Write-Host "Mimikatz signature test file"
""",
        "mime_type": "application/x-powershell",
        "description": "Contains Mimikatz-like strings for AMSI/EDR detection testing.",
        "mitre_technique_id": "T1003.001",
        "expected_detection": "amsi,edr",
        "safety_level": SafetyLevel.SIGNATURE,
        "endpoint": "stage",
    },
    {
        "name": "Reverse Shell Template",
        "filename": "reverse-shell.ps1",
        "category": PayloadCategory.SCRIPT,
        "subcategory": "powershell",
        "content": b"""# EICAR Test - Reverse Shell Template
# Contains patterns that should trigger EDR detection
# NO actual network connectivity

$EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Reverse shell pattern (non-functional - uses localhost)
$testHost = "127.0.0.1"
$testPort = 4444

Write-Host "Reverse shell test file - connects nowhere"
Write-Host $EICAR

# Pattern that looks like reverse shell (doesn't actually run)
# $client = New-Object System.Net.Sockets.TCPClient($testHost, $testPort)
""",
        "mime_type": "application/x-powershell",
        "description": "Reverse shell template for EDR detection testing.",
        "mitre_technique_id": "T1059.001",
        "expected_detection": "edr",
        "safety_level": SafetyLevel.SIGNATURE,
        "endpoint": "stage",
    },
    {
        "name": "Batch Payload",
        "filename": "payload.bat",
        "category": PayloadCategory.SCRIPT,
        "subcategory": "batch",
        "content": b"""@echo off
REM EICAR Test Batch File
REM This file contains the EICAR test string

echo X5O!P%%@AP[4\\PZX54(P^^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
echo EICAR test executed successfully
pause
""",
        "mime_type": "application/x-msdos-program",
        "description": "Batch file containing EICAR test string.",
        "mitre_technique_id": "T1059.003",
        "expected_detection": "av",
        "safety_level": SafetyLevel.SAFE,
        "endpoint": "stage",
    },

    # === DOCUMENTS ===
    {
        "name": "Malicious Document (PDF)",
        "filename": "document.pdf",
        "category": PayloadCategory.DOCUMENT,
        "subcategory": "pdf",
        # Minimal PDF with EICAR in stream
        "content": b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 68 >>
stream
X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
endstream
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000206 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
324
%%EOF
""",
        "mime_type": "application/pdf",
        "description": "PDF document containing EICAR test string. Tests sandbox/proxy detection.",
        "mitre_technique_id": "T1566.001",
        "expected_detection": "sandbox",
        "safety_level": SafetyLevel.SAFE,
        "endpoint": "download",
    },

    # === ARCHIVES ===
    {
        "name": "Archive with EICAR",
        "filename": "package.zip",
        "category": PayloadCategory.ARCHIVE,
        "subcategory": "zip",
        # We'll generate this dynamically
        "content": None,  # Generated in seed function
        "mime_type": "application/zip",
        "description": "ZIP archive containing EICAR test file. Tests archive scanning.",
        "mitre_technique_id": "T1204.002",
        "expected_detection": "av",
        "safety_level": SafetyLevel.SAFE,
        "endpoint": "download",
    },

    # === DISGUISED FILES ===
    {
        "name": "Disguised Executable (PDF extension)",
        "filename": "invoice.pdf.exe",
        "category": PayloadCategory.DISGUISED,
        "subcategory": "double_extension",
        "content": EICAR_STRING.encode('ascii'),
        "mime_type": "application/x-dosexec",
        "description": "Executable disguised with .pdf extension. Tests double-extension detection.",
        "mitre_technique_id": "T1036.007",
        "expected_detection": "proxy,av",
        "safety_level": SafetyLevel.SAFE,
        "endpoint": "download",
    },
    {
        "name": "Disguised Executable (Image extension)",
        "filename": "photo.jpg.exe",
        "category": PayloadCategory.DISGUISED,
        "subcategory": "double_extension",
        "content": EICAR_STRING.encode('ascii'),
        "mime_type": "application/x-dosexec",
        "description": "Executable disguised with .jpg extension. Tests double-extension detection.",
        "mitre_technique_id": "T1036.007",
        "expected_detection": "proxy,av",
        "safety_level": SafetyLevel.SAFE,
        "endpoint": "download",
    },
]


def generate_zip_with_eicar() -> bytes:
    """Generate a ZIP file containing the EICAR test string."""
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('eicar.com', EICAR_STRING)
    return buffer.getvalue()


def seed_payloads(db: Session) -> int:
    """Seed the database with pre-built payloads."""
    storage_path = settings.STORAGE_PATH
    seeded_count = 0

    for payload_def in SEED_PAYLOADS:
        filename = payload_def["filename"]

        # Check if already exists
        existing = db.query(Payload).filter(Payload.filename == filename).first()
        if existing:
            continue

        # Get or generate content
        content = payload_def["content"]
        if content is None and filename == "package.zip":
            content = generate_zip_with_eicar()

        if content is None:
            continue

        # Determine file path based on endpoint
        endpoint = payload_def.get("endpoint", "download")
        file_dir = storage_path / endpoint
        file_dir.mkdir(parents=True, exist_ok=True)
        file_path = file_dir / filename

        # Write file to storage
        with open(file_path, 'wb') as f:
            f.write(content)

        # Calculate SHA256
        sha256 = hashlib.sha256(content).hexdigest()

        # Create database record
        payload = Payload(
            id=uuid4(),
            name=payload_def["name"],
            filename=filename,
            category=payload_def["category"],
            subcategory=payload_def.get("subcategory"),
            file_path=str(file_path),
            mime_type=payload_def["mime_type"],
            file_size=len(content),
            sha256=sha256,
            description=payload_def.get("description"),
            mitre_technique_id=payload_def.get("mitre_technique_id"),
            expected_detection=payload_def.get("expected_detection"),
            safety_level=payload_def.get("safety_level", SafetyLevel.SAFE),
            enabled=True,
        )

        db.add(payload)
        seeded_count += 1

    db.commit()
    return seeded_count


def ensure_payloads_seeded(db: Session) -> int:
    """Ensure payloads are seeded, return count of new payloads."""
    return seed_payloads(db)
