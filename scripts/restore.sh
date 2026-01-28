#!/bin/bash
# Cloud Relay Restore — PostgreSQL + Docker volumes
# Usage: ./scripts/restore.sh <backup_path>
# Example: ./scripts/restore.sh ./backups/20260128-020000
set -euo pipefail

BACKUP_PATH="${1:?Usage: $0 <backup_path>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

if [ ! -d "${BACKUP_PATH}" ]; then
    echo "ERROR: Backup directory not found: ${BACKUP_PATH}"
    exit 1
fi

# Load .env for database credentials
if [ -f "${PROJECT_DIR}/.env" ]; then
    set -a
    # shellcheck source=/dev/null
    source "${PROJECT_DIR}/.env"
    set +a
fi

POSTGRES_USER="${POSTGRES_USER:-relay}"
POSTGRES_DB="${POSTGRES_DB:-relay}"

echo "=== Cloud Relay Restore ==="
echo "Source: ${BACKUP_PATH}"

if [ -f "${BACKUP_PATH}/manifest.json" ]; then
    echo "Backup timestamp: $(python3 -c "import json; print(json.load(open('${BACKUP_PATH}/manifest.json'))['timestamp'])")"
fi

echo ""
read -rp "This will OVERWRITE current data. Continue? [y/N] " confirm
if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# 1. Restore PostgreSQL
echo ""
echo "[1/3] Restoring PostgreSQL..."
if [ -f "${BACKUP_PATH}/relay-db.dump" ]; then
    if docker ps --format '{{.Names}}' | grep -q relay-db; then
        docker exec -i relay-db pg_restore \
            -U "${POSTGRES_USER}" \
            -d "${POSTGRES_DB}" \
            --clean --if-exists \
            < "${BACKUP_PATH}/relay-db.dump"
        echo "  OK: relay-db restored"
    else
        echo "  ERROR: relay-db container not running. Start services first."
        exit 1
    fi
else
    echo "  SKIP: relay-db.dump not found"
fi

if [ -f "${BACKUP_PATH}/msf-db.dump" ]; then
    docker exec -i relay-db pg_restore \
        -U "${POSTGRES_USER}" \
        -d msf \
        --clean --if-exists \
        < "${BACKUP_PATH}/msf-db.dump"
    echo "  OK: msf-db restored"
fi

# 2. Restore volumes
echo "[2/3] Restoring volumes..."
for volume in relay-db-data payload-storage c2-payloads; do
    FULL_VOL="mirqab-cloud-relay_${volume}"
    if [ -f "${BACKUP_PATH}/${volume}.tar.gz" ]; then
        # Ensure volume exists
        docker volume create "${FULL_VOL}" &>/dev/null || true
        docker run --rm \
            -v "${FULL_VOL}:/target" \
            -v "$(realpath "${BACKUP_PATH}"):/backup:ro" \
            alpine \
            sh -c "rm -rf /target/* && tar xzf /backup/${volume}.tar.gz -C /target"
        echo "  OK: ${volume} restored"
    else
        echo "  SKIP: ${volume}.tar.gz not found"
    fi
done

# 3. Restore configs
echo "[3/3] Restoring configs..."
if [ -f "${BACKUP_PATH}/configs.tar.gz" ]; then
    echo "  Config backup available at: ${BACKUP_PATH}/configs.tar.gz"
    echo "  To restore: tar xzf ${BACKUP_PATH}/configs.tar.gz -C ${PROJECT_DIR}"
    echo "  (Not auto-restored to avoid overwriting current configs)"
fi

echo ""
echo "=== Restore complete ==="
echo "Restart services: docker compose down && docker compose up -d"
