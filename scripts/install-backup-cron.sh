#!/bin/bash
# Install backup cron job — runs daily at 2:00 AM
# Usage: ./scripts/install-backup-cron.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_SCRIPT="${SCRIPT_DIR}/backup.sh"
LOG_FILE="${PROJECT_DIR}/backups/backup.log"

mkdir -p "${PROJECT_DIR}/backups"

CRON_ENTRY="0 2 * * * ${BACKUP_SCRIPT} >> ${LOG_FILE} 2>&1"

# Check if already installed
if crontab -l 2>/dev/null | grep -q "backup.sh"; then
    echo "Backup cron already installed:"
    crontab -l | grep backup.sh
    echo ""
    read -rp "Replace existing cron entry? [y/N] " confirm
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    # Remove old entry
    crontab -l | grep -v "backup.sh" | crontab -
fi

# Install
(crontab -l 2>/dev/null; echo "${CRON_ENTRY}") | crontab -

echo "Backup cron installed:"
echo "  Schedule: Daily at 02:00"
echo "  Script:   ${BACKUP_SCRIPT}"
echo "  Log:      ${LOG_FILE}"
echo "  Retention: ${RETENTION_DAYS:-30} days"
echo ""
echo "Verify: crontab -l"
