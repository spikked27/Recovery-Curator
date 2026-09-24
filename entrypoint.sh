#!/bin/sh
set -eu

groupmod -o -g "${PGID}" users 2>/dev/null || true
useradd -o -u "${PUID}" -g "${PGID}" -M -s /usr/sbin/nologin curator 2>/dev/null || true

validate_subpath() {
    value=$1
    name=$2
    case "${value}" in
        ""|/*|..|../*|*/../*|*/..)
            echo "ERROR: ${name} must be a non-empty relative path without '..': ${value}" >&2
            exit 1
            ;;
    esac
}

shared_target() {
    subpath=$1
    name=$2
    validate_subpath "${subpath}" "${name}"
    target=$(readlink -m -- "${RECOVERY_DATA_ROOT}/${subpath}")
    case "${target}" in
        "${shared_root}"|"${shared_root}"/*) ;;
        *)
            echo "ERROR: ${name} resolves outside RECOVERY_DATA_ROOT: ${target}" >&2
            exit 1
            ;;
    esac
    printf '%s\n' "${target}"
}

link_shared_path() {
    alias_path=$1
    target_path=$2
    label=$3
    create_target=$4
    if [ "${create_target}" = "true" ]; then
        mkdir -p -- "${target_path}"
    elif [ ! -d "${target_path}" ]; then
        echo "ERROR: ${label} does not exist beneath the shared recovery root: ${target_path}" >&2
        exit 1
    fi
    if [ -e "${alias_path}" ] || [ -L "${alias_path}" ]; then
        echo "ERROR: ${alias_path} already exists. Remove the legacy Docker mapping for ${alias_path} when shared-workspace mode is enabled." >&2
        exit 1
    fi
    ln -s -- "${target_path}" "${alias_path}"
}

# Hardlinks cannot cross separate Docker bind-mount boundaries, even when both
# host paths report the same device. Shared-workspace mode mounts their common
# host parent once, then exposes stable aliases so existing catalog paths remain
# valid across the migration.
if [ -n "${RECOVERY_DATA_ROOT:-}" ]; then
    if [ ! -d "${RECOVERY_DATA_ROOT}" ]; then
        echo "ERROR: RECOVERY_DATA_ROOT is not mounted as a directory: ${RECOVERY_DATA_ROOT}" >&2
        exit 1
    fi
    shared_root=$(readlink -f -- "${RECOVERY_DATA_ROOT}")
    source_target=$(shared_target "${SOURCE_SUBPATH:-}" SOURCE_SUBPATH)
    output_target=$(shared_target "${OUTPUT_SUBPATH:-}" OUTPUT_SUBPATH)
    quarantine_target=$(shared_target "${QUARANTINE_SUBPATH:-}" QUARANTINE_SUBPATH)
    link_shared_path "${SOURCE_ROOT}" "${source_target}" "Recovered Source" false
    link_shared_path "${OUTPUT_ROOT}" "${output_target}" "Curated Output" true
    link_shared_path "${QUARANTINE_ROOT}" "${quarantine_target}" "Quarantine" true
    if [ -n "${REFERENCE_SUBPATH:-}" ]; then
        reference_target=$(shared_target "${REFERENCE_SUBPATH}" REFERENCE_SUBPATH)
        link_shared_path "${REFERENCE_ROOT}" "${reference_target}" "Known-Good Root" false
    fi
    echo "Shared recovery workspace enabled at ${shared_root}; hardlinks can be used when the host filesystem permits them."
fi

mkdir -p "${DATA_DIR}" "${OUTPUT_ROOT}" "${QUARANTINE_ROOT}"
# Never recursively chown mounted libraries: on an Unraid array that can trigger
# parity-protected metadata writes across every existing file at each startup.
chown "${PUID}:${PGID}" "${DATA_DIR}" "${QUARANTINE_ROOT}"
chown "${OUTPUT_UID:-${PUID}}:${OUTPUT_GID:-${PGID}}" "${OUTPUT_ROOT}"
umask "${UMASK}"
exec gosu "${PUID}:${PGID}" "$@"
