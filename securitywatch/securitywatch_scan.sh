#!/usr/bin/env bash
# Copyright Roman Glos 2026
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

normalize_lang() {
  local value="${1:-de}"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    de|en) printf '%s' "$value" ;;
    *) printf 'de' ;;
  esac
}

OUTPUT_LANG="$(normalize_lang "${OUTPUT_LANG:-${LANGUAGE:-de}}")"

say() {
  local de_text="$1"
  local en_text="$2"
  if [[ "$OUTPUT_LANG" == "en" ]]; then
    echo "$en_text"
  else
    echo "$de_text"
  fi
}

if [[ ! -f "$ENV_FILE" ]]; then
  say "FEHLER: ${ENV_FILE} nicht gefunden. Bitte die .env anlegen und anpassen." "ERROR: ${ENV_FILE} not found. Please create and adjust the .env file." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

OUTPUT_LANG="$(normalize_lang "${OUTPUT_LANG:-${LANGUAGE:-de}}")"

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

exec > >(tee -a "$SCAN_LOG") 2>&1

say "[$(date '+%F %T')] SecurityWatch-Scan gestartet" "[$(date '+%F %T')] SecurityWatch scan started"
say "Run-Verzeichnis: $RUN_DIR" "Run directory: $RUN_DIR"

docker version >/dev/null

IGNORE_UNFIXED_ARGS=()
if [[ "${TRIVY_IGNORE_UNFIXED:-0}" == "1" ]]; then
  IGNORE_UNFIXED_ARGS+=(--ignore-unfixed)
fi

SEVERITY_ARGS=(--severity "$TRIVY_SEVERITIES")
TIMEOUT_ARGS=(--timeout "$TRIVY_TIMEOUT")

scan_host_fs() {
  say "[$(date '+%F %T')] Starte Rootfs-Scan des Hosts" "[$(date '+%F %T')] Starting host rootfs scan"
  docker run --rm \
    -v "$CACHE_DIR:/root/.cache/trivy" \
    -v "/:/host:ro" \
    -v "$RUN_DIR:/reports" \
    "$TRIVY_IMAGE" \
    rootfs /host \
    --format json \
    --output /reports/host_rootfs.json \
    "${SEVERITY_ARGS[@]}" \
    "${TIMEOUT_ARGS[@]}" \
    "${IGNORE_UNFIXED_ARGS[@]}" \
    --scanners vuln \
    --skip-dirs "$TRIVY_SKIP_DIRS"
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
      image "$image" \
      --format json \
      --output "/reports/image_${safe_name}.json" \
      "${SEVERITY_ARGS[@]}" \
      "${TIMEOUT_ARGS[@]}" \
      "${IGNORE_UNFIXED_ARGS[@]}" \
      --scanners vuln
  done
}

if [[ "${TRIVY_SCAN_FILESYSTEM:-1}" == "1" ]]; then
  scan_host_fs
fi

if [[ "${TRIVY_SCAN_IMAGES:-1}" == "1" ]]; then
  scan_images
fi

say "[$(date '+%F %T')] Erzeuge Zusammenfassung" "[$(date '+%F %T')] Creating summary"
python3 "${SCRIPT_DIR}/securitywatch_report.py" \
  --run-dir "$RUN_DIR" \
  --summary-json "$SUMMARY_JSON" \
  --mail-txt "$MAIL_TXT" \
  --mail-html "$MAIL_HTML" \
  --env-file "$ENV_FILE" \
  --lang "$OUTPUT_LANG"

say "[$(date '+%F %T')] Versende Mail" "[$(date '+%F %T')] Sending email"
python3 "${SCRIPT_DIR}/securitywatch_mail.py" \
  --env-file "$ENV_FILE" \
  --summary-json "$SUMMARY_JSON" \
  --mail-txt "$MAIL_TXT" \
  --mail-html "$MAIL_HTML"

say "[$(date '+%F %T')] SecurityWatch-Scan beendet" "[$(date '+%F %T')] SecurityWatch scan finished"
