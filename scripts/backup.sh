#!/bin/bash
# Cloud Relay Backup — PostgreSQL + Docker volumes
# Usage: ./scripts/backup.sh [backup_dir]
# Cron:  0 2 * * * /home/relay/mirqab-cloud-relay/scripts/backup.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${1:-${PROJECT_DIR}/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"

# Load .env for database credentials
if [ -f "${PROJECT_DIR}/.env" ]; then
    set -a
    # shellcheck source=/dev/null
    source "${PROJECT_DIR}/.env"
    set +a
fi

POSTGRES_USER="${POSTGRES_USER:-relay}"
POSTGRES_DB="${POSTGRES_DB:-relay}"

mkdir -p "${BACKUP_PATH}"

echo "=== Cloud Relay Backup — ${TIMESTAMP} ==="

# 1. PostgreSQL dump
echo "[1/3] Backing up PostgreSQL..."
if docker ps --format '{{.Names}}' | grep -q relay-db; then
    docker exec relay-db pg_dump \
        -U "${POSTGRES_USER}" \
        -d "${POSTGRES_DB}" \
        --format=custom \
        --compress=9 \
        > "${BACKUP_PATH}/relay-db.dump"
    echo "  OK: relay-db.dump ($(du -h "${BACKUP_PATH}/relay-db.dump" | cut -f1))"

    # Also dump msf database if it exists
    if docker exec relay-db psql -U "${POSTGRES_USER}" -lqt | grep -q msf; then
        docker exec relay-db pg_dump \
            -U "${POSTGRES_USER}" \
            -d msf \
            --format=custom \
            --compress=9 \
            > "${BACKUP_PATH}/msf-db.dump"
        echo "  OK: msf-db.dump ($(du -h "${BACKUP_PATH}/msf-db.dump" | cut -f1))"
    fi
else
    echo "  SKIP: relay-db container not running"
fi

# 2. Docker volume data (payload storage)
echo "[2/3] Backing up volumes..."
for volume in relay-db-data payload-storage c2-payloads; do
    FULL_VOL="mirqab-cloud-relay_${volume}"
    if docker volume inspect "${FULL_VOL}" &>/dev/null; then
        docker run --rm \
            -v "${FULL_VOL}:/source:ro" \
            -v "${BACKUP_PATH}:/backup" \
            alpine \
            tar czf "/backup/${volume}.tar.gz" -C /source .
        echo "  OK: ${volume}.tar.gz ($(du -h "${BACKUP_PATH}/${volume}.tar.gz" | cut -f1))"
    else
        echo "  SKIP: volume ${FULL_VOL} not found"
    fi
done

# 3. Config files
echo "[3/3] Backing up configs..."
tar czf "${BACKUP_PATH}/configs.tar.gz" \
    -C "${PROJECT_DIR}" \
    --exclude='.git' \
    --exclude='backups' \
    --exclude='__pycache__' \
    .env \
    traefik/ \
    monitoring/ \
    docker-compose.yml \
    docker-compose.monitoring.yml \
    2>/dev/null || true
echo "  OK: configs.tar.gz"

# Create manifest
cat > "${BACKUP_PATH}/manifest.json" <<MANIFEST
{
    "timestamp": "${TIMESTAMP}",
    "hostname": "$(hostname)",
    "files": $(ls -1 "${BACKUP_PATH}" | grep -v manifest | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip().split('\n')))"),
    "total_size": "$(du -sh "${BACKUP_PATH}" | cut -f1)"
}
MANIFEST

# Retention — delete backups older than N days
echo ""
echo "Applying retention policy (${RETENTION_DAYS} days)..."
DELETED=0
find "${BACKUP_DIR}" -maxdepth 1 -type d -mtime "+${RETENTION_DAYS}" | while read -r old_backup; do
    [ "${old_backup}" = "${BACKUP_DIR}" ] && continue
    rm -rf "${old_backup}"
    echo "  Deleted: $(basename "${old_backup}")"
    DELETED=$((DELETED + 1))
done
echo "  Cleaned up old backups."

echo ""
TOTAL_SIZE="$(du -sh "${BACKUP_PATH}" | cut -f1)"
echo "=== Backup complete: ${BACKUP_PATH} (${TOTAL_SIZE}) ==="
