#!/usr/bin/env bash
#
# compare.sh — Run Trivy, Grype, Kubescape and Plexar over the SAME set of
# images on an air-gapped CRI-O Kubernetes node (e.g. an on-prem appliance), so
# their findings can be compared apples-to-apples.
#
# Design goals:
#   * Runs as root on the node (needs CRI-O socket + crictl + skopeo).
#   * Fully offline — every scanner is invoked with DB auto-update disabled.
#     You MUST pre-seed the vuln DBs on the node first (see bench/README.md).
#   * Scans the identical CRI-O image tarball with every tool. No re-pulling.
#   * Produces raw JSON only. Analysis/normalisation happens off-box in
#     analyze.py, so nothing here depends on jq/python being on the appliance.
#
# Usage:
#   NAMESPACES="app-tier data-tier gateway" ./compare.sh
#   # or scan everything the node has:
#   IMAGES_FROM=crictl ./compare.sh
#
set -uo pipefail

# ---- config (override via env) ----------------------------------------------
OUT="${OUT:-./bench-results}"
NAMESPACES="${NAMESPACES:-}"                 # space-separated; empty => all ns via kubectl
IMAGES_FROM="${IMAGES_FROM:-kubectl}"        # kubectl | crictl
SEVERITY="${SEVERITY:-CRITICAL,HIGH,MEDIUM}"
TMPDIR_TARS="${TMPDIR_TARS:-/tmp/bench-tars}"
KEEP_TARS="${KEEP_TARS:-0}"

# tool binaries (override if not in PATH)
TRIVY="${TRIVY:-trivy}"
GRYPE="${GRYPE:-grype}"
KUBESCAPE="${KUBESCAPE:-kubescape}"
PLEXAR="${PLEXAR:-plexar}"
CRICTL="${CRICTL:-crictl}"
SKOPEO="${SKOPEO:-skopeo}"
KUBECTL="${KUBECTL:-kubectl}"

# offline knobs
export GRYPE_DB_AUTO_UPDATE=false
export GRYPE_DB_VALIDATE_AGE=false
export GRYPE_CHECK_FOR_APP_UPDATE=false

log()  { printf '\033[36m[bench]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[bench] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[bench] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

slug() { echo "$1" | tr '/:@' '___' | tr -cd '[:alnum:]_.-'; }

# ---- preconditions ----------------------------------------------------------
check_bin() { command -v "$1" >/dev/null 2>&1 && echo "yes" || echo "no"; }

log "recording tool versions -> $OUT/versions.txt"
mkdir -p "$OUT"/{trivy,grype} "$TMPDIR_TARS"
{
  echo "date: $(date -u +%FT%TZ)"
  echo "node: $(uname -a)"
  for b in "$TRIVY" "$GRYPE" "$KUBESCAPE" "$PLEXAR" "$CRICTL" "$SKOPEO"; do
    printf '%s: ' "$b"; "$b" --version 2>&1 | head -1 || echo "MISSING"
  done
} > "$OUT/versions.txt"
cat "$OUT/versions.txt" >&2

[ "$(check_bin "$CRICTL")" = yes ] || die "crictl not found (required for CRI-O image discovery/export)"
[ "$(check_bin "$SKOPEO")" = yes ] || die "skopeo not found (required to export CRI-O images to tar)"
[ -S /run/crio/crio.sock ] || warn "/run/crio/crio.sock not found — are you on a CRI-O node?"

# ---- 1. discover the image set ----------------------------------------------
declare -A IMG_SEEN
IMAGES=()
add_img() { local i="$1"; [ -n "$i" ] || return; [ -z "${IMG_SEEN[$i]:-}" ] || return; IMG_SEEN[$i]=1; IMAGES+=("$i"); }

if [ "$IMAGES_FROM" = crictl ]; then
  log "discovering images from crictl (all node images)"
  while read -r ref; do add_img "$ref"; done < <(
    "$CRICTL" images -o json 2>/dev/null \
      | tr ',' '\n' | grep -o '"[^"]*/[^"]*:[^"]*"' | tr -d '"' | sort -u
  )
else
  [ "$(check_bin "$KUBECTL")" = yes ] || die "kubectl not found; set IMAGES_FROM=crictl to use node images"
  ns_list="$NAMESPACES"
  if [ -z "$ns_list" ]; then
    log "no NAMESPACES set — enumerating all namespaces via kubectl"
    ns_list="$("$KUBECTL" get ns -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}' 2>/dev/null)"
  fi
  log "discovering images from namespaces: $ns_list"
  for ns in $ns_list; do
    while read -r ref; do add_img "$ref"; done < <(
      "$KUBECTL" get pods -n "$ns" -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null | sort -u
    )
  done
fi

[ "${#IMAGES[@]}" -gt 0 ] || die "no images discovered"
log "discovered ${#IMAGES[@]} unique images"
printf '%s\n' "${IMAGES[@]}" > "$OUT/images.txt"

# ---- 2. resolve + export each image from CRI-O, scan with trivy & grype ------
# Resolve a pod image ref to a CRI-O containers-storage reference by fuzzy
# matching against `crictl images` (mirrors Plexar's CRIOResolver).
resolve_crio() {
  local want="$1" base tag
  # exact
  if "$CRICTL" images -o json 2>/dev/null | grep -q "\"$want\""; then echo "$want"; return; fi
  base="${want##*/}"; base="${base%%:*}"; tag="${want##*:}"
  "$CRICTL" images -o json 2>/dev/null | tr ',' '\n' \
    | grep -o '"[^"]*/[^"]*:[^"]*"' | tr -d '"' \
    | while read -r ref; do
        local rb rt; rb="${ref##*/}"; rb="${rb%%:*}"; rt="${ref##*:}"
        if [ "$rb" = "$base" ] && [ "$rt" = "$tag" ]; then echo "$ref"; return 0; fi
      done | head -1
}

i=0
for img in "${IMAGES[@]}"; do
  i=$((i+1)); s="$(slug "$img")"
  ref="$(resolve_crio "$img")"; ref="${ref:-$img}"
  tar="$TMPDIR_TARS/$s.tar"
  log "[$i/${#IMAGES[@]}] export $img (crio: $ref)"
  if ! "$SKOPEO" copy "containers-storage:$ref" "docker-archive:$tar" >/dev/null 2>&1; then
    warn "skopeo export failed for $ref — skipping"; continue
  fi

  if [ "$(check_bin "$TRIVY")" = yes ]; then
    "$TRIVY" image --input "$tar" --severity "$SEVERITY" --scanners vuln \
      --offline-scan --skip-db-update --quiet --no-progress \
      --format json -o "$OUT/trivy/$s.json" 2>>"$OUT/trivy.err" \
      || warn "trivy failed on $img (see $OUT/trivy.err)"
  fi
  if [ "$(check_bin "$GRYPE")" = yes ]; then
    "$GRYPE" "docker-archive:$tar" -o json > "$OUT/grype/$s.json" 2>>"$OUT/grype.err" \
      || warn "grype failed on $img (see $OUT/grype.err)"
  fi
  [ "$KEEP_TARS" = 1 ] || rm -f "$tar"
done

# ---- 3. kubescape (namespace/cluster config + image scan) -------------------
if [ "$(check_bin "$KUBESCAPE")" = yes ]; then
  ks_ns_args=""
  [ -n "$NAMESPACES" ] && for ns in $NAMESPACES; do ks_ns_args="$ks_ns_args --include-namespaces $ns"; done
  log "running kubescape scan (offline; requires 'kubescape download artifacts' pre-run)"
  # shellcheck disable=SC2086
  "$KUBESCAPE" scan $ks_ns_args --format json --output "$OUT/kubescape.json" \
    >/dev/null 2>>"$OUT/kubescape.err" || warn "kubescape failed (see $OUT/kubescape.err)"
else
  warn "kubescape not found — skipping"
fi

# ---- 4. plexar (the tool under test) ----------------------------------------
if [ "$(check_bin "$PLEXAR")" = yes ]; then
  ns_csv="$(echo "$NAMESPACES" | tr ' ' ',')"
  log "running plexar scan (image-source crio)"
  if [ -n "$ns_csv" ]; then
    "$PLEXAR" scan -n "$ns_csv" --image-source crio -o json > "$OUT/plexar.json" 2>>"$OUT/plexar.err" \
      || warn "plexar failed (see $OUT/plexar.err)"
  else
    "$PLEXAR" scan --all-namespaces --image-source crio -o json > "$OUT/plexar.json" 2>>"$OUT/plexar.err" \
      || warn "plexar failed (see $OUT/plexar.err)"
  fi
else
  warn "plexar not found — skipping"
fi

log "DONE. Raw results in: $OUT"
log "Copy $OUT off the node, then run:  python3 bench/analyze.py $OUT"
