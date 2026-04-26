#!/usr/bin/env bash
# =============================================================================
# UGREEN SecurityWatch Scan
#
# DE:
#   Ein einziges Script fuer den kompletten Standardablauf:
#     1. Trivy-Image pruefen/aktualisieren, sofern aktiviert
#     2. Docker vor dem Scan bereinigen, ohne Container oder Volumes zu loeschen
#     3. aktuelles Trivy-Image behalten, alte unbenutzte Images entfernen
#     4. Host-Dateisystem und Images laufender Container scannen
#     5. Zusatzreport fuer lokale selbst gebaute Images erzeugen
#     6. Bericht und Mail im bekannten Format erzeugen
#     7. alte Report-Ordner gemaess .env-Regeln entfernen
#
# EN:
#   One single script for the complete default workflow:
#     1. check/update the Trivy image if enabled
#     2. clean up Docker before the scan without deleting containers or volumes
#     3. keep the current Trivy image, remove old unused images
#     4. scan the host filesystem and images of running containers
#     5. create an additional report for locally built images
#     6. generate the report and email in the known format
#     7. remove old report folders according to .env rules
#
# Copyright Roman Glos 2026
# =============================================================================

set -euo pipefail

SCRIPT_VERSION="2.4.3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

DRY_RUN="false"
ARG_NO_CLEANUP="false"
ARG_NO_PRUNE_UNUSED_IMAGES="false"
ARG_NO_PRUNE_BUILD_CACHE="false"
ARG_NO_TRIVY_PULL="false"
ARG_NO_MAIL="false"
ARG_NO_REPORT_CLEANUP="false"
ARG_NO_LOCAL_IMAGE_REPORT="false"
CURRENT_TRIVY_IMAGE_ID=""

normalize_lang() {
  local value="${1:-de}"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    de|en) printf '%s' "$value" ;;
    *) printf 'de' ;;
  esac
}

OUTPUT_LANG="de"

say() {
  local de_text="$1"
  local en_text="$2"
  if [[ "$OUTPUT_LANG" == "en" ]]; then
    echo "$en_text"
  else
    echo "$de_text"
  fi
}

load_env_for_language_and_config() {
  if [[ ! -f "$ENV_FILE" ]]; then
    say "FEHLER: ${ENV_FILE} nicht gefunden. Bitte die .env anlegen und anpassen." "ERROR: ${ENV_FILE} not found. Please create and adjust the .env file." >&2
    exit 1
  fi

  # shellcheck disable=SC1090
  source "$ENV_FILE"
  OUTPUT_LANG="$(normalize_lang "${OUTPUT_LANG:-${LANGUAGE:-de}}")"
}

print_usage() {
  if [[ "$OUTPUT_LANG" == "en" ]]; then
    cat <<'USAGE_EN'
SecurityWatch Scan for UGREEN UGOS

Usage:
  ./securitywatch_scan.sh [options]

Default workflow without options:
  1. check/update the Trivy image if enabled
  2. remove unused Docker images while keeping the current Trivy image
  3. remove Docker build cache
  4. scan the host filesystem and running Docker images
  5. create an additional report for locally built images
  6. generate report and email in the known format
  7. remove old report folders according to .env rules

Options:
  --dry-run                    Show what would be done, but do not clean up or scan
  --no-cleanup                 Disable Docker cleanup before the scan
  --no-prune-unused-images     Remove dangling images only instead of all unused images
  --no-prune-build-cache       Do not remove Docker build cache
  --no-trivy-pull              Do not update the Trivy image before the scan
  --no-mail                    Generate scan and report, but do not send email
  --no-report-cleanup          Do not remove old report folders
  --no-local-image-report      Do not create the locally built image package report
  --help, -h, --               Show this help

Useful .env values:
  OUTPUT_LANG=en
  TRIVY_IMAGE=ghcr.io/aquasecurity/trivy:latest
  TRIVY_AUTO_PULL_IMAGE=1
  TRIVY_SKIP_VERSION_CHECK=0
  DOCKER_CLEANUP_BEFORE_SCAN=1
  DOCKER_PRUNE_UNUSED_IMAGES=1
  DOCKER_PRUNE_BUILD_CACHE=1
  LOCAL_IMAGE_REPORT_ENABLED=1
  LOCAL_IMAGE_INCLUDE_PATTERNS=
  LOCAL_IMAGE_EXCLUDE_PATTERNS=
  REPORT_CLEANUP_ENABLED=1
  REPORT_RETENTION_DAYS=30
  REPORT_KEEP_LAST=10
USAGE_EN
  else
    cat <<'USAGE_DE'
SecurityWatch Scan fuer UGREEN UGOS

Aufruf:
  ./securitywatch_scan.sh [Optionen]

Standardablauf ohne Optionen:
  1. Trivy-Image pruefen/aktualisieren, sofern aktiviert
  2. unbenutzte Docker-Images entfernen, aktuelles Trivy-Image behalten
  3. Docker-Build-Cache entfernen
  4. Host-Dateisystem und laufende Docker-Images scannen
  5. Zusatzreport fuer lokale selbst gebaute Images erzeugen
  6. Report und Mail im bekannten Format erzeugen
  7. alte Report-Ordner gemaess .env-Regeln entfernen

Optionen:
  --dry-run                    Nur anzeigen/loggen, nichts bereinigen und keinen Scan starten
  --no-cleanup                 Docker-Bereinigung vor dem Scan deaktivieren
  --no-prune-unused-images     Nur dangling Images statt aller unbenutzten Images entfernen
  --no-prune-build-cache       Docker-Build-Cache nicht bereinigen
  --no-trivy-pull              Trivy-Image vor dem Scan nicht aktualisieren
  --no-mail                    Scan und Report erzeugen, aber keine Mail versenden
  --no-report-cleanup          Alte Report-Ordner nicht entfernen
  --no-local-image-report      Kein Zusatzreport fuer lokale selbst gebaute Images
  --help, -h, --               Hilfe anzeigen

Sinnvolle .env-Werte:
  OUTPUT_LANG=de
  TRIVY_IMAGE=ghcr.io/aquasecurity/trivy:latest
  TRIVY_AUTO_PULL_IMAGE=1
  TRIVY_SKIP_VERSION_CHECK=0
  DOCKER_CLEANUP_BEFORE_SCAN=1
  DOCKER_PRUNE_UNUSED_IMAGES=1
  DOCKER_PRUNE_BUILD_CACHE=1
  LOCAL_IMAGE_REPORT_ENABLED=1
  LOCAL_IMAGE_INCLUDE_PATTERNS=
  LOCAL_IMAGE_EXCLUDE_PATTERNS=
  REPORT_CLEANUP_ENABLED=1
  REPORT_RETENTION_DAYS=30
  REPORT_KEEP_LAST=10
USAGE_DE
  fi
}

load_env_for_language_and_config

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN="true"
      ;;
    --no-cleanup)
      ARG_NO_CLEANUP="true"
      ;;
    --no-prune-unused-images)
      ARG_NO_PRUNE_UNUSED_IMAGES="true"
      ;;
    --no-prune-build-cache)
      ARG_NO_PRUNE_BUILD_CACHE="true"
      ;;
    --no-trivy-pull)
      ARG_NO_TRIVY_PULL="true"
      ;;
    --no-mail)
      ARG_NO_MAIL="true"
      ;;
    --no-report-cleanup)
      ARG_NO_REPORT_CLEANUP="true"
      ;;
    --no-local-image-report)
      ARG_NO_LOCAL_IMAGE_REPORT="true"
      ;;
    --help|-h|--)
      print_usage
      exit 0
      ;;
    *)
      say "Unbekannte Option: $1" "Unknown option: $1" >&2
      print_usage >&2
      exit 2
      ;;
  esac
  shift
done

REPORT_DIR="${REPORT_DIR:-${SCRIPT_DIR}/reports}"
CACHE_DIR="${CACHE_DIR:-${SCRIPT_DIR}/trivy-cache}"
STATE_DIR="${STATE_DIR:-${SCRIPT_DIR}/state}"
TRIVY_IMAGE="${TRIVY_IMAGE:-ghcr.io/aquasecurity/trivy:latest}"
TRIVY_SEVERITIES="${TRIVY_SEVERITIES:-HIGH,CRITICAL}"
TRIVY_TIMEOUT="${TRIVY_TIMEOUT:-60m}"
TRIVY_IGNORE_UNFIXED="${TRIVY_IGNORE_UNFIXED:-0}"
TRIVY_SCAN_FILESYSTEM="${TRIVY_SCAN_FILESYSTEM:-1}"
TRIVY_SCAN_IMAGES="${TRIVY_SCAN_IMAGES:-1}"
TRIVY_AUTO_PULL_IMAGE="${TRIVY_AUTO_PULL_IMAGE:-1}"
TRIVY_SKIP_VERSION_CHECK="${TRIVY_SKIP_VERSION_CHECK:-0}"
TRIVY_SKIP_DIRS="${TRIVY_SKIP_DIRS:-}"

DOCKER_CLEANUP_BEFORE_SCAN="${DOCKER_CLEANUP_BEFORE_SCAN:-1}"
DOCKER_PRUNE_UNUSED_IMAGES="${DOCKER_PRUNE_UNUSED_IMAGES:-1}"
DOCKER_PRUNE_BUILD_CACHE="${DOCKER_PRUNE_BUILD_CACHE:-1}"
LOCAL_IMAGE_REPORT_ENABLED="${LOCAL_IMAGE_REPORT_ENABLED:-1}"
LOCAL_IMAGE_INCLUDE_PATTERNS="${LOCAL_IMAGE_INCLUDE_PATTERNS:-}"
LOCAL_IMAGE_EXCLUDE_PATTERNS="${LOCAL_IMAGE_EXCLUDE_PATTERNS:-}"

REPORT_CLEANUP_ENABLED="${REPORT_CLEANUP_ENABLED:-1}"
REPORT_RETENTION_DAYS="${REPORT_RETENTION_DAYS:-30}"
REPORT_KEEP_LAST="${REPORT_KEEP_LAST:-10}"

if [[ "$ARG_NO_CLEANUP" == "true" ]]; then
  DOCKER_CLEANUP_BEFORE_SCAN="0"
fi
if [[ "$ARG_NO_PRUNE_UNUSED_IMAGES" == "true" ]]; then
  DOCKER_PRUNE_UNUSED_IMAGES="0"
fi
if [[ "$ARG_NO_PRUNE_BUILD_CACHE" == "true" ]]; then
  DOCKER_PRUNE_BUILD_CACHE="0"
fi
if [[ "$ARG_NO_TRIVY_PULL" == "true" ]]; then
  TRIVY_AUTO_PULL_IMAGE="0"
fi
if [[ "$ARG_NO_REPORT_CLEANUP" == "true" ]]; then
  REPORT_CLEANUP_ENABLED="0"
fi
if [[ "$ARG_NO_LOCAL_IMAGE_REPORT" == "true" ]]; then
  LOCAL_IMAGE_REPORT_ENABLED="0"
fi

mkdir -p "$REPORT_DIR" "$CACHE_DIR" "$STATE_DIR"

TIMESTAMP="$(date +%F_%H-%M-%S)"
RUN_DIR="${REPORT_DIR}/${TIMESTAMP}"
mkdir -p "$RUN_DIR"

SCAN_LOG="${RUN_DIR}/scan.log"
SUMMARY_JSON="${RUN_DIR}/summary.json"
MAIL_TXT="${RUN_DIR}/mail.txt"
MAIL_HTML="${RUN_DIR}/mail.html"
IMAGES_JSONL="${RUN_DIR}/images_scanned.txt"
IMAGE_MAP_TSV="${RUN_DIR}/images_map.tsv"
CONTAINERS_TXT="${RUN_DIR}/containers_running.txt"
LOCAL_IMAGES_TXT="${RUN_DIR}/local-built-images.txt"
LOCAL_IMAGES_TSV="${RUN_DIR}/local-built-images.tsv"
LOCAL_IMAGE_FINDINGS_TXT="${RUN_DIR}/local-built-image-findings.txt"
LOCAL_IMAGE_FINDINGS_TSV="${RUN_DIR}/local-built-image-findings.tsv"

exec > >(tee -a "$SCAN_LOG") 2>&1

log() {
  echo "[$(date '+%F %T')] $*"
}

is_uint() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

to_bool_enabled() {
  local value="${1:-0}"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

run_cmd() {
  local cmd="$1"
  log "CMD: $cmd"

  if [[ "$DRY_RUN" == "true" ]]; then
    say "DRY-RUN: Befehl nicht ausgefuehrt." "DRY-RUN: Command not executed."
    return 0
  fi

  set +e
  bash -lc "$cmd"
  local rc=$?
  set -e

  if [[ "$rc" -ne 0 ]]; then
    say "WARNUNG: Befehl beendet mit Exitcode $rc" "WARNING: Command exited with code $rc"
  fi

  return "$rc"
}

save_docker_state() {
  local suffix="$1"

  docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' \
    > "${RUN_DIR}/containers-${suffix}.txt" 2>/dev/null || true

  docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' \
    > "${RUN_DIR}/containers-all-${suffix}.txt" 2>/dev/null || true

  docker images -a \
    > "${RUN_DIR}/images-${suffix}.txt" 2>/dev/null || true

  docker images --filter dangling=true \
    > "${RUN_DIR}/dangling-images-${suffix}.txt" 2>/dev/null || true

  docker system df \
    > "${RUN_DIR}/docker-system-df-${suffix}.txt" 2>/dev/null || true

  docker builder du \
    > "${RUN_DIR}/docker-builder-du-${suffix}.txt" 2>/dev/null || true
}

refresh_current_trivy_image_id() {
  CURRENT_TRIVY_IMAGE_ID="$(docker image inspect "$TRIVY_IMAGE" --format '{{.Id}}' 2>/dev/null || true)"
  if [[ -n "$CURRENT_TRIVY_IMAGE_ID" ]]; then
    say "Aktuelles Trivy-Image wird bei der Bereinigung behalten: ${TRIVY_IMAGE}" "Current Trivy image will be kept during cleanup: ${TRIVY_IMAGE}"
  else
    say "Hinweis: Aktuelles Trivy-Image ist lokal noch nicht vorhanden: ${TRIVY_IMAGE}" "Note: Current Trivy image is not available locally yet: ${TRIVY_IMAGE}"
  fi
}

pull_trivy_image() {
  if ! to_bool_enabled "$TRIVY_AUTO_PULL_IMAGE"; then
    say "Trivy-Image-Aktualisierung ist deaktiviert." "Trivy image update is disabled."
    refresh_current_trivy_image_id
    return 0
  fi

  say "[$(date '+%F %T')] Pruefe Trivy-Image auf Updates: ${TRIVY_IMAGE}" "[$(date '+%F %T')] Checking Trivy image for updates: ${TRIVY_IMAGE}"
  say "Docker laedt nur neue Layer herunter, wenn wirklich ein neueres Image vorhanden ist." "Docker only downloads new layers if a newer image is actually available."
  run_cmd "docker pull '$TRIVY_IMAGE'" || say "WARNUNG: Trivy-Image konnte nicht aktualisiert werden. Der Scan versucht das lokal vorhandene Image zu verwenden." "WARNING: Trivy image could not be updated. The scan will try to use the locally available image."
  refresh_current_trivy_image_id
}

collect_used_image_ids() {
  docker ps -a -q 2>/dev/null | while IFS= read -r cid; do
    [[ -n "$cid" ]] || continue
    docker inspect "$cid" --format '{{.Image}}' 2>/dev/null || true
  done | sort -u
}

cleanup_unused_images_safely() {
  local prune_all="$1"
  local used_ids_file="${RUN_DIR}/used-image-ids.txt"
  local candidates_file="${RUN_DIR}/image-prune-candidates.txt"
  local kept_file="${RUN_DIR}/image-prune-kept.txt"
  local removed_file="${RUN_DIR}/image-prune-removed.txt"
  local failed_file="${RUN_DIR}/image-prune-failed.txt"

  : > "$candidates_file"
  : > "$kept_file"
  : > "$removed_file"
  : > "$failed_file"

  collect_used_image_ids > "$used_ids_file" || true

  say "Analysiere unbenutzte Docker-Images. Das aktuelle Trivy-Image wird nicht entfernt." "Analyzing unused Docker images. The current Trivy image will not be removed."

  local deleted=0
  local kept=0
  local failed=0
  local id repo tag size ref reason

  while IFS='|' read -r id repo tag size; do
    [[ -n "${id:-}" ]] || continue

    if grep -Fxq "$id" "$used_ids_file" 2>/dev/null; then
      printf '%s\t%s:%s\t%s\t%s\n' "$id" "$repo" "$tag" "$size" "used-by-container" >> "$kept_file"
      kept=$((kept + 1))
      continue
    fi

    if [[ -n "$CURRENT_TRIVY_IMAGE_ID" && "$id" == "$CURRENT_TRIVY_IMAGE_ID" ]]; then
      printf '%s\t%s:%s\t%s\t%s\n' "$id" "$repo" "$tag" "$size" "current-trivy-image" >> "$kept_file"
      kept=$((kept + 1))
      continue
    fi

    reason="unused"
    if [[ "$repo" == "<none>" || "$tag" == "<none>" ]]; then
      ref="$id"
      reason="dangling-or-untagged"
    else
      ref="${repo}:${tag}"
    fi

    if [[ "$prune_all" != "true" && "$reason" != "dangling-or-untagged" ]]; then
      printf '%s\t%s\t%s\t%s\n' "$id" "$ref" "$size" "kept-unused-tagged-image" >> "$kept_file"
      kept=$((kept + 1))
      continue
    fi

    printf '%s\t%s\t%s\t%s\n' "$id" "$ref" "$size" "$reason" >> "$candidates_file"

    if [[ "$DRY_RUN" == "true" ]]; then
      say "DRY-RUN: wuerde unbenutztes Image entfernen: $ref" "DRY-RUN: would remove unused image: $ref"
      deleted=$((deleted + 1))
      continue
    fi

    if docker image rm "$ref" >> "$removed_file" 2>> "$failed_file"; then
      say "Unbenutztes Image entfernt: $ref" "Unused image removed: $ref"
      deleted=$((deleted + 1))
    else
      say "WARNUNG: Image konnte nicht entfernt werden: $ref" "WARNING: Image could not be removed: $ref"
      failed=$((failed + 1))
    fi
  done < <(docker image ls -a --no-trunc --format '{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}' 2>/dev/null | sort -u)

  say "Image-Bereinigung beendet. Kandidaten/entfernt: ${deleted}, behalten: ${kept}, Fehler: ${failed}." "Image cleanup finished. Candidates/removed: ${deleted}, kept: ${kept}, errors: ${failed}."
}

cleanup_docker_before_scan() {
  if ! to_bool_enabled "$DOCKER_CLEANUP_BEFORE_SCAN"; then
    say "Docker-Bereinigung vor dem Scan ist deaktiviert." "Docker cleanup before scan is disabled."
    return 0
  fi

  say "[$(date '+%F %T')] Starte Docker-Bereinigung vor dem Scan" "[$(date '+%F %T')] Starting Docker cleanup before scan"
  save_docker_state "before-cleanup"
  refresh_current_trivy_image_id

  if to_bool_enabled "$DOCKER_PRUNE_UNUSED_IMAGES"; then
    say "Entferne alle unbenutzten Docker-Images. Container, Volumes und das aktuelle Trivy-Image werden nicht geloescht." "Removing all unused Docker images. Containers, volumes and the current Trivy image will not be deleted."
    cleanup_unused_images_safely "true" || say "WARNUNG: Docker-Image-Bereinigung fehlgeschlagen. Der Scan wird trotzdem fortgesetzt." "WARNING: Docker image cleanup failed. The scan will continue anyway."
  else
    say "Entferne nur dangling Docker-Images. Container, Volumes und das aktuelle Trivy-Image werden nicht geloescht." "Removing dangling Docker images only. Containers, volumes and the current Trivy image will not be deleted."
    cleanup_unused_images_safely "false" || say "WARNUNG: Docker-Image-Bereinigung fehlgeschlagen. Der Scan wird trotzdem fortgesetzt." "WARNING: Docker image cleanup failed. The scan will continue anyway."
  fi

  if to_bool_enabled "$DOCKER_PRUNE_BUILD_CACHE"; then
    say "Entferne ungenutzten Docker-Build-Cache." "Removing unused Docker build cache."
    run_cmd "docker builder prune -f" || say "WARNUNG: Docker-Build-Cache-Bereinigung fehlgeschlagen. Der Scan wird trotzdem fortgesetzt." "WARNING: Docker build cache cleanup failed. The scan will continue anyway."
  else
    say "Docker-Build-Cache wird nicht bereinigt." "Docker build cache cleanup is disabled."
  fi

  save_docker_state "after-cleanup"
  say "[$(date '+%F %T')] Docker-Bereinigung beendet" "[$(date '+%F %T')] Docker cleanup finished"
}

cleanup_old_reports() {
  if ! to_bool_enabled "$REPORT_CLEANUP_ENABLED"; then
    say "Report-Aufraeumen ist deaktiviert." "Report cleanup is disabled."
    return 0
  fi

  if ! is_uint "$REPORT_RETENTION_DAYS"; then
    say "WARNUNG: REPORT_RETENTION_DAYS ist ungueltig. Verwende 30 Tage." "WARNING: REPORT_RETENTION_DAYS is invalid. Using 30 days."
    REPORT_RETENTION_DAYS="30"
  fi

  if ! is_uint "$REPORT_KEEP_LAST"; then
    say "WARNUNG: REPORT_KEEP_LAST ist ungueltig. Verwende 10 Reports." "WARNING: REPORT_KEEP_LAST is invalid. Using 10 reports."
    REPORT_KEEP_LAST="10"
  fi

  say "[$(date '+%F %T')] Raeume alte Report-Ordner auf" "[$(date '+%F %T')] Cleaning up old report directories"
  say "Report-Aufbewahrung: ${REPORT_RETENTION_DAYS} Tage, mindestens ${REPORT_KEEP_LAST} letzte Reports behalten" "Report retention: ${REPORT_RETENTION_DAYS} days, always keep at least the latest ${REPORT_KEEP_LAST} reports"

  mapfile -t report_dirs < <(
    find "$REPORT_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
      | while IFS= read -r dir; do
          base="$(basename "$dir")"
          if [[ "$base" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}$ ]]; then
            printf '%s\n' "$dir"
          fi
        done \
      | sort -r
  )

  if [[ ${#report_dirs[@]} -eq 0 ]]; then
    say "Keine passenden Report-Ordner gefunden." "No matching report directories found."
    return 0
  fi

  declare -A keep_dirs=()
  local i
  for ((i = 0; i < ${#report_dirs[@]} && i < REPORT_KEEP_LAST; i++)); do
    keep_dirs["${report_dirs[$i]}"]=1
  done

  local deleted=0
  local kept=0
  local dir

  for dir in "${report_dirs[@]}"; do
    if [[ -n "${keep_dirs[$dir]:-}" || "$dir" == "$RUN_DIR" || "$REPORT_RETENTION_DAYS" -eq 0 ]]; then
      kept=$((kept + 1))
      continue
    fi

    if find "$dir" -maxdepth 0 -type d -mtime "+${REPORT_RETENTION_DAYS}" 2>/dev/null | grep -q .; then
      if [[ "$DRY_RUN" == "true" ]]; then
        say "DRY-RUN: wuerde alten Report-Ordner entfernen: $dir" "DRY-RUN: would remove old report directory: $dir"
      else
        rm -rf -- "$dir"
        say "Alter Report-Ordner entfernt: $dir" "Old report directory removed: $dir"
      fi
      deleted=$((deleted + 1))
    else
      kept=$((kept + 1))
    fi
  done

  say "Report-Aufraeumen beendet. Entfernt: ${deleted}, behalten: ${kept}." "Report cleanup finished. Removed: ${deleted}, kept: ${kept}."
}


trim_spaces() {
  local value="${1:-}"
  value="${value#${value%%[![:space:]]*}}"
  value="${value%${value##*[![:space:]]}}"
  printf '%s' "$value"
}

matches_csv_glob_patterns() {
  local value="$1"
  local patterns_csv="${2:-}"
  local pattern

  [[ -n "$value" && -n "$patterns_csv" ]] || return 1

  local old_ifs="$IFS"
  IFS=','
  for pattern in $patterns_csv; do
    pattern="$(trim_spaces "$pattern")"
    [[ -n "$pattern" ]] || continue
    if [[ "$value" == $pattern ]]; then
      IFS="$old_ifs"
      return 0
    fi
  done
  IFS="$old_ifs"
  return 1
}

looks_like_local_built_image() {
  local image_ref="$1"
  local project="$2"
  local service="$3"

  [[ -n "$image_ref" ]] || return 1

  # Explicit user override: exclude wins over include and auto-detection.
  if matches_csv_glob_patterns "$image_ref" "$LOCAL_IMAGE_EXCLUDE_PATTERNS"; then
    return 1
  fi

  if matches_csv_glob_patterns "$image_ref" "$LOCAL_IMAGE_INCLUDE_PATTERNS"; then
    return 0
  fi

  # Common convention for local helper images.
  if [[ "$image_ref" == *":local" ]]; then
    return 0
  fi

  # Docker Compose default build image names, when no external image: was set.
  # This is generic and does not assume a specific package or project name.
  if [[ -n "$project" && -n "$service" ]]; then
    if [[ "$image_ref" == "${project}-${service}" || "$image_ref" == "${project}-${service}:"* ]]; then
      return 0
    fi
    if [[ "$image_ref" == "${project}_${service}" || "$image_ref" == "${project}_${service}:"* ]]; then
      return 0
    fi
  fi

  return 1
}

collect_local_built_images() {
  if ! to_bool_enabled "$LOCAL_IMAGE_REPORT_ENABLED"; then
    say "Zusatzreport fuer lokale selbst gebaute Images ist deaktiviert." "Additional report for locally built images is disabled."
    : > "$LOCAL_IMAGES_TXT"
    : > "$LOCAL_IMAGES_TSV"
    return 0
  fi

  say "[$(date '+%F %T')] Ermittle lokale selbst gebaute Images" "[$(date '+%F %T')] Detecting locally built images"
  : > "$LOCAL_IMAGES_TXT"
  : > "$LOCAL_IMAGES_TSV"

  local cid name image_ref project service
  while IFS= read -r cid; do
    [[ -n "$cid" ]] || continue
    name="$(docker inspect "$cid" --format '{{.Name}}' 2>/dev/null | sed 's#^/##')"
    image_ref="$(docker inspect "$cid" --format '{{.Config.Image}}' 2>/dev/null || true)"
    project="$(docker inspect "$cid" --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null || true)"
    service="$(docker inspect "$cid" --format '{{index .Config.Labels "com.docker.compose.service"}}' 2>/dev/null || true)"

    if looks_like_local_built_image "$image_ref" "$project" "$service"; then
      printf '%s\t%s\t%s\t%s\n' "$image_ref" "$name" "$project" "$service" >> "$LOCAL_IMAGES_TSV"
      printf '%s\n' "$image_ref" >> "$LOCAL_IMAGES_TXT"
    fi
  done < <(docker ps -q 2>/dev/null)

  sort -u -o "$LOCAL_IMAGES_TXT" "$LOCAL_IMAGES_TXT" 2>/dev/null || true
  sort -u -o "$LOCAL_IMAGES_TSV" "$LOCAL_IMAGES_TSV" 2>/dev/null || true

  if [[ ! -s "$LOCAL_IMAGES_TXT" ]]; then
    say "Keine lokalen selbst gebauten Images erkannt." "No locally built images detected."
    return 0
  fi

  say "Lokale selbst gebaute Images:" "Locally built images:"
  while IFS= read -r image_ref; do
    [[ -n "$image_ref" ]] || continue
    echo "  - $image_ref"
  done < "$LOCAL_IMAGES_TXT"
}

scan_host_fs() {
  say "[$(date '+%F %T')] Starte Rootfs-Scan des Hosts" "[$(date '+%F %T')] Starting host rootfs scan"
  docker run --rm \
    -v "$CACHE_DIR:/root/.cache/trivy" \
    -v "/:/host:ro" \
    -v "$RUN_DIR:/reports" \
    "$TRIVY_IMAGE" \
    "${TRIVY_VERSION_ARGS[@]}" \
    rootfs /host \
    --format json \
    --output /reports/host_rootfs.json \
    "${SEVERITY_ARGS[@]}" \
    "${TIMEOUT_ARGS[@]}" \
    "${IGNORE_UNFIXED_ARGS[@]}" \
    "${SKIP_DIR_ARGS[@]}" \
    --scanners vuln
}

get_running_images() {
  docker ps --format '{{.Names}}|{{.Image}}' \
    | awk -F'|' '
        NF >= 2 {
          name=$1
          image=$2
          if (name != "" && image != "") {
            print name "|" image
          }
        }
      '
}

scan_images() {
  say "[$(date '+%F %T')] Ermittle zu scannende Docker-Images aus laufenden Containern" "[$(date '+%F %T')] Determining Docker images to scan from running containers"

  mapfile -t RUNNING < <(get_running_images | sort -u)

  if [[ ${#RUNNING[@]} -eq 0 ]]; then
    say "[$(date '+%F %T')] Keine laufenden Container gefunden" "[$(date '+%F %T')] No running containers found"
    : > "$IMAGES_JSONL"
    : > "$IMAGE_MAP_TSV"
    : > "$CONTAINERS_TXT"
    return 0
  fi

  printf '%s\n' "${RUNNING[@]}" > "$CONTAINERS_TXT"

  mapfile -t IMAGES < <(printf '%s\n' "${RUNNING[@]}" | cut -d'|' -f2 | sort -u)

  if [[ ${#IMAGES[@]} -eq 0 ]]; then
    say "[$(date '+%F %T')] Keine Docker-Images gefunden" "[$(date '+%F %T')] No Docker images found"
    : > "$IMAGES_JSONL"
    : > "$IMAGE_MAP_TSV"
    return 0
  fi

  printf '%s\n' "${IMAGES[@]}" > "$IMAGES_JSONL"
  : > "$IMAGE_MAP_TSV"

  say "[$(date '+%F %T')] Laufende Container:" "[$(date '+%F %T')] Running containers:"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local_name="${line%%|*}"
    local_image="${line#*|}"
    echo "  - ${local_name} -> ${local_image}"
  done < "$CONTAINERS_TXT"

  local idx=0
  for image in "${IMAGES[@]}"; do
    idx=$((idx + 1))
    local safe_name
    safe_name="$(printf '%03d_%s' "$idx" "$(echo "$image" | sed 's#[/:@]#_#g')")"
    printf '%s\t%s\n' "$safe_name" "$image" >> "$IMAGE_MAP_TSV"

    say "[$(date '+%F %T')] [${idx}/${#IMAGES[@]}] Scanne Image: $image" "[$(date '+%F %T')] [${idx}/${#IMAGES[@]}] Scanning image: $image"

    docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$CACHE_DIR:/root/.cache/trivy" \
      -v "$RUN_DIR:/reports" \
      "$TRIVY_IMAGE" \
      "${TRIVY_VERSION_ARGS[@]}" \
      image "$image" \
      --format json \
      --output "/reports/image_${safe_name}.json" \
      "${SEVERITY_ARGS[@]}" \
      "${TIMEOUT_ARGS[@]}" \
      "${IGNORE_UNFIXED_ARGS[@]}" \
      --scanners vuln
  done
}

create_local_image_findings_report() {
  if ! to_bool_enabled "$LOCAL_IMAGE_REPORT_ENABLED"; then
    return 0
  fi

  if [[ ! -s "$LOCAL_IMAGES_TXT" ]]; then
    return 0
  fi

  say "[$(date '+%F %T')] Erzeuge Zusatzreport fuer lokale selbst gebaute Images" "[$(date '+%F %T')] Creating additional report for locally built images"

  python3 - "$RUN_DIR" "$LOCAL_IMAGES_TXT" "$OUTPUT_LANG" "$LOCAL_IMAGE_FINDINGS_TXT" "$LOCAL_IMAGE_FINDINGS_TSV" <<'PY_LOCAL_REPORT'
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

run_dir = Path(sys.argv[1])
local_images_file = Path(sys.argv[2])
lang = sys.argv[3]
out_txt = Path(sys.argv[4])
out_tsv = Path(sys.argv[5])

local_images = {line.strip() for line in local_images_file.read_text(encoding='utf-8').splitlines() if line.strip()}

image_map = {}
map_file = run_dir / 'images_map.tsv'
if map_file.exists():
    for line in map_file.read_text(encoding='utf-8').splitlines():
        if '\t' not in line:
            continue
        safe, image = line.split('\t', 1)
        image_map[safe.strip()] = image.strip()

severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}


def extract_score(vuln: Dict[str, Any]) -> Optional[float]:
    best: Optional[float] = None
    cvss = vuln.get('CVSS') or {}
    if isinstance(cvss, dict):
        for value in cvss.values():
            if not isinstance(value, dict):
                continue
            for key in ('V3Score', 'V2Score'):
                raw = value.get(key)
                if isinstance(raw, (int, float)):
                    best = max(best, float(raw)) if best is not None else float(raw)
    for key in ('CVSSScore', 'Score'):
        raw = vuln.get(key)
        if isinstance(raw, (int, float)):
            best = max(best, float(raw)) if best is not None else float(raw)
    return best


def score_text(score: Optional[float]) -> str:
    return '-' if score is None else f'{score:.1f}'

rows = []
seen = set()

for path in sorted(run_dir.glob('image_*.json')):
    safe = path.stem.replace('image_', '', 1)
    image = image_map.get(safe)
    if image not in local_images:
        continue

    try:
        doc = json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        continue

    for result in doc.get('Results') or []:
        target = result.get('Target') or '-'
        for vuln in result.get('Vulnerabilities') or []:
            fixed = vuln.get('FixedVersion') or ''
            if not fixed:
                continue
            cve = vuln.get('VulnerabilityID') or '-'
            sev = vuln.get('Severity') or 'UNKNOWN'
            pkg = vuln.get('PkgName') or '-'
            inst = vuln.get('InstalledVersion') or '-'
            score = extract_score(vuln)
            key = (image, cve, sev, pkg, inst, fixed, target)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                'image': image,
                'severity': sev,
                'score': score,
                'score_text': score_text(score),
                'cve': cve,
                'pkg': pkg,
                'installed': inst,
                'fixed': fixed,
                'target': target,
            })

rows.sort(key=lambda r: (r['image'], severity_order.get(r['severity'], 5), -(r['score'] if r['score'] is not None else -1), r['pkg'], r['cve']))

with out_tsv.open('w', encoding='utf-8') as f:
    f.write('Image\tSeverity\tCVSS\tCVE\tPackage\tInstalled\tFixed\tTarget\n')
    for r in rows:
        f.write(f"{r['image']}\t{r['severity']}\t{r['score_text']}\t{r['cve']}\t{r['pkg']}\t{r['installed']}\t{r['fixed']}\t{r['target']}\n")

lines = []
if lang == 'en':
    lines.append('Additional report for locally built images')
    lines.append('Only findings with an available fixed version are listed.')
else:
    lines.append('Zusatzreport fuer lokale selbst gebaute Images')
    lines.append('Es werden nur Funde mit verfuegbarer Fix-Version aufgelistet.')
lines.append('')

if not local_images:
    lines.append('No locally built images detected.' if lang == 'en' else 'Keine lokalen selbst gebauten Images erkannt.')
elif not rows:
    lines.append('No fixable package findings for locally built images.' if lang == 'en' else 'Keine behebbaren Paket-Funde fuer lokale selbst gebaute Images.')
else:
    by_image = {}
    for r in rows:
        by_image.setdefault(r['image'], []).append(r)
    for image, items in by_image.items():
        crit = sum(1 for r in items if r['severity'] == 'CRITICAL')
        high = sum(1 for r in items if r['severity'] == 'HIGH')
        if lang == 'en':
            lines.append(f'{image}: {len(items)} fixable findings ({crit} critical, {high} high)')
        else:
            lines.append(f'{image}: {len(items)} behebbare Funde ({crit} kritisch, {high} hoch)')
        for r in items[:25]:
            lines.append(f"  - {r['severity']} CVSS {r['score_text']} {r['cve']} | {r['pkg']} | {r['installed']} -> {r['fixed']} | {r['target']}")
        if len(items) > 25:
            more = len(items) - 25
            lines.append(f'  ... {more} more entries in TSV file' if lang == 'en' else f'  ... {more} weitere Eintraege in der TSV-Datei')
        lines.append('')

out_txt.write_text('\n'.join(lines) + '\n', encoding='utf-8')
print('\n'.join(lines[:80]))
PY_LOCAL_REPORT
}

say "[$(date '+%F %T')] SecurityWatch-Scan gestartet" "[$(date '+%F %T')] SecurityWatch scan started"
say "Version: ${SCRIPT_VERSION}" "Version: ${SCRIPT_VERSION}"
say "Run-Verzeichnis: $RUN_DIR" "Run directory: $RUN_DIR"
say "Trivy-Image: $TRIVY_IMAGE" "Trivy image: $TRIVY_IMAGE"
say "Docker-Cleanup vor Scan: $DOCKER_CLEANUP_BEFORE_SCAN" "Docker cleanup before scan: $DOCKER_CLEANUP_BEFORE_SCAN"
say "Unbenutzte Images entfernen: $DOCKER_PRUNE_UNUSED_IMAGES" "Remove unused images: $DOCKER_PRUNE_UNUSED_IMAGES"
say "Build-Cache entfernen: $DOCKER_PRUNE_BUILD_CACHE" "Remove build cache: $DOCKER_PRUNE_BUILD_CACHE"
say "Trivy Auto-Pull: $TRIVY_AUTO_PULL_IMAGE" "Trivy auto-pull: $TRIVY_AUTO_PULL_IMAGE"
say "Lokaler Image-Zusatzreport: $LOCAL_IMAGE_REPORT_ENABLED" "Local image additional report: $LOCAL_IMAGE_REPORT_ENABLED"
if [[ -n "$LOCAL_IMAGE_INCLUDE_PATTERNS" ]]; then
  say "Lokale Image-Include-Muster: $LOCAL_IMAGE_INCLUDE_PATTERNS" "Local image include patterns: $LOCAL_IMAGE_INCLUDE_PATTERNS"
fi
if [[ -n "$LOCAL_IMAGE_EXCLUDE_PATTERNS" ]]; then
  say "Lokale Image-Exclude-Muster: $LOCAL_IMAGE_EXCLUDE_PATTERNS" "Local image exclude patterns: $LOCAL_IMAGE_EXCLUDE_PATTERNS"
fi
say "Report-Aufraeumen: $REPORT_CLEANUP_ENABLED" "Report cleanup: $REPORT_CLEANUP_ENABLED"
say "Dry-Run: $DRY_RUN" "Dry run: $DRY_RUN"
say "Ausgabesprache: $OUTPUT_LANG" "Output language: $OUTPUT_LANG"

docker version >/dev/null

pull_trivy_image
cleanup_docker_before_scan
collect_local_built_images

if [[ "$DRY_RUN" == "true" ]]; then
  cleanup_old_reports
  say "DRY-RUN beendet. Scan, Report und Mail wurden nicht ausgefuehrt." "DRY-RUN finished. Scan, report and email were not executed."
  exit 0
fi

IGNORE_UNFIXED_ARGS=()
if to_bool_enabled "$TRIVY_IGNORE_UNFIXED"; then
  IGNORE_UNFIXED_ARGS+=(--ignore-unfixed)
fi

TRIVY_VERSION_ARGS=()
if to_bool_enabled "$TRIVY_SKIP_VERSION_CHECK"; then
  TRIVY_VERSION_ARGS+=(--skip-version-check)
fi

SEVERITY_ARGS=(--severity "$TRIVY_SEVERITIES")
TIMEOUT_ARGS=(--timeout "$TRIVY_TIMEOUT")
SKIP_DIR_ARGS=()
if [[ -n "${TRIVY_SKIP_DIRS:-}" ]]; then
  SKIP_DIR_ARGS+=(--skip-dirs "$TRIVY_SKIP_DIRS")
fi

if to_bool_enabled "$TRIVY_SCAN_FILESYSTEM"; then
  scan_host_fs
else
  say "Host-Dateisystem-Scan ist deaktiviert." "Host filesystem scan is disabled."
fi

if to_bool_enabled "$TRIVY_SCAN_IMAGES"; then
  scan_images
else
  say "Docker-Image-Scan ist deaktiviert." "Docker image scan is disabled."
fi

create_local_image_findings_report

say "[$(date '+%F %T')] Erzeuge Zusammenfassung" "[$(date '+%F %T')] Creating summary"
python3 "${SCRIPT_DIR}/securitywatch_report.py" \
  --run-dir "$RUN_DIR" \
  --summary-json "$SUMMARY_JSON" \
  --mail-txt "$MAIL_TXT" \
  --mail-html "$MAIL_HTML" \
  --env-file "$ENV_FILE" \
  --lang "$OUTPUT_LANG" \
  --script-version "$SCRIPT_VERSION"

if [[ "$ARG_NO_MAIL" == "true" ]]; then
  say "Mailversand wurde per --no-mail uebersprungen." "Email sending was skipped via --no-mail."
else
  say "[$(date '+%F %T')] Versende Mail" "[$(date '+%F %T')] Sending email"
  python3 "${SCRIPT_DIR}/securitywatch_mail.py" \
    --env-file "$ENV_FILE" \
    --summary-json "$SUMMARY_JSON" \
    --mail-txt "$MAIL_TXT" \
    --mail-html "$MAIL_HTML"
fi

cleanup_old_reports

say "[$(date '+%F %T')] SecurityWatch-Scan beendet" "[$(date '+%F %T')] SecurityWatch scan finished"
