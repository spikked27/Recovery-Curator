#!/bin/sh
set -eu

groupmod -o -g "${PGID}" users 2>/dev/null || true
useradd -o -u "${PUID}" -g "${PGID}" -M -s /usr/sbin/nologin curator 2>/dev/null || true
mkdir -p "${DATA_DIR}" "${OUTPUT_ROOT}" "${QUARANTINE_ROOT}"
# Never recursively chown mounted libraries: on an Unraid array that can trigger
# parity-protected metadata writes across every existing file at each startup.
chown "${PUID}:${PGID}" "${DATA_DIR}" "${OUTPUT_ROOT}" "${QUARANTINE_ROOT}"
umask "${UMASK}"
exec gosu "${PUID}:${PGID}" "$@"
