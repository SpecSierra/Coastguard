#!/usr/bin/env bash
# Scan one RPM with ClamAV and YARA. The package is only unpacked, never
# installed or executed.
#
# usage: scan.sh <package.rpm> <yara-rules> <clamav-db-dir> <report-dir>
#        <yara-rules> is a .yar file or a directory of .yar files
# exit:  0 clean, 1 detections, 2 scan error (verdict unknown)
set -euo pipefail

if [ $# -ne 4 ]; then
    echo "usage: $0 <package.rpm> <yara-rules> <clamav-db-dir> <report-dir>" >&2
    exit 2
fi

rpm_file=$(realpath "$1")
rules=$(realpath "$2")
clamdb=$(realpath "$3")
mkdir -p "$4"
report=$(realpath "$4")

work=$(mktemp -d)
trap 'chmod -R u+rwX "$work" 2>/dev/null || true; rm -rf "$work"' EXIT
mkdir "$work/payload"

errors=()

# --- metadata ---------------------------------------------------------------
sha256=$(sha256sum "$rpm_file" | cut -d' ' -f1)
if ! rpm -qp --nosignature --qf \
    'Name: %{NAME}\nVersion: %{VERSION}-%{RELEASE}\nArch: %{ARCH}\nVendor: %{VENDOR}\nPackager: %{PACKAGER}\nURL: %{URL}\nLicense: %{LICENSE}\nBuildHost: %{BUILDHOST}\nBuildTime: %{BUILDTIME:date}\n' \
    "$rpm_file" > "$report/rpm-info.txt" 2> "$report/rpm-error.log"; then
    echo "not a readable RPM: $(head -n1 "$report/rpm-error.log")" >&2
    exit 2
fi
rm -f "$report/rpm-error.log"
name=$(rpm -qp --nosignature --qf '%{NAME}' "$rpm_file")
nevra=$(rpm -qp --nosignature --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$rpm_file")

# Install scriptlets run as root on the device, so they are scanned too.
rpm -qp --nosignature --scripts --triggers --filetriggers "$rpm_file" \
    > "$work/scriptlets.txt" 2>/dev/null || errors+=("could not read scriptlets")
cp "$work/scriptlets.txt" "$report/scriptlets.txt"

# --- unpack -----------------------------------------------------------------
# bsdtar reads RPM directly and refuses absolute paths, ".." and writes
# through symlinks, which rpm2cpio | cpio does not guarantee.
if ! bsdtar -xf "$rpm_file" -C "$work/payload" --no-same-owner \
    --no-same-permissions 2> "$report/extract.log"; then
    errors+=("payload extraction failed or was incomplete")
fi
[ -s "$report/extract.log" ] || rm -f "$report/extract.log"
chmod -R u+rwX "$work/payload"
# Listing comes from the header so original modes and owners (setuid!) show.
rpm -qp --nosignature -lv "$rpm_file" > "$report/files.txt" 2>/dev/null || true
file_count=$(find "$work/payload" -mindepth 1 | wc -l)

targets=("$rpm_file" "$work/payload" "$work/scriptlets.txt")
# Keep temp paths out of the logs.
clean_paths() { sed -e "s|$work/||g" -e "s|$rpm_file|$(basename "$rpm_file")|g"; }

# --- ClamAV -----------------------------------------------------------------
set +e
clamscan --database="$clamdb" --recursive --infected \
    --follow-dir-symlinks=0 --follow-file-symlinks=0 \
    --max-filesize=1024M --max-scansize=2048M --max-recursion=20 \
    "${targets[@]}" 2>&1 | clean_paths > "$report/clamav.log"
clam_rc=${PIPESTATUS[0]}
set -e
[ "$clam_rc" -le 1 ] || errors+=("clamscan exited with $clam_rc")
grep ' FOUND$' "$report/clamav.log" > "$report/clamav-detections.txt" || true
clam_hits=$(wc -l < "$report/clamav-detections.txt")

# --- YARA -------------------------------------------------------------------
: > "$report/yara-detections.txt"
: > "$work/yara.err"
if [ -d "$rules" ]; then rule_files=("$rules"/*.yar); else rule_files=("$rules"); fi
if yarac -w "${rule_files[@]}" "$work/rules.yarc" 2>> "$work/yara.err"; then
    for target in "${targets[@]}"; do
        # -N: do not follow symlinks out of the payload
        yara -C -r -N -w "$work/rules.yarc" "$target" 2>> "$work/yara.err" \
            | clean_paths >> "$report/yara-detections.txt" \
            || errors+=("yara failed on $(basename "$target")")
    done
else
    errors+=("could not compile YARA rules")
fi
if [ -s "$work/yara.err" ]; then
    clean_paths < "$work/yara.err" > "$report/yara-error.log"
fi
yara_hits=$(wc -l < "$report/yara-detections.txt")

# --- verdict ----------------------------------------------------------------
# Detections win over errors: a partial scan that still found something is a hit.
if [ $((clam_hits + yara_hits)) -gt 0 ]; then
    verdict=detected; rc=1
elif [ ${#errors[@]} -gt 0 ]; then
    verdict=error; rc=2
else
    verdict=clean; rc=0
fi

jq -n \
    --arg verdict "$verdict" --arg sha256 "$sha256" --arg package "$nevra" \
    --arg name "$name" \
    --arg source "${RPM_URL:-}" --arg scanned "$(date -u +%FT%TZ)" \
    --arg yara_rules "${YARA_RULES_VERSION:-unknown}" \
    --arg clamav "$(clamscan --database="$clamdb" --version 2>/dev/null || true)" \
    --argjson files "$file_count" \
    --rawfile clam "$report/clamav-detections.txt" \
    --rawfile yara "$report/yara-detections.txt" \
    --args '{
        verdict: $verdict, name: $name, package: $package, sha256: $sha256,
        source: $source,
        scanned: $scanned, files: $files,
        engines: {clamav: $clamav, yara_forge_core: $yara_rules},
        clamav: ($clam | split("\n") | map(select(. != ""))),
        yara: ($yara | split("\n") | map(select(. != ""))),
        errors: $ARGS.positional
    }' "${errors[@]}" > "$report/report.json"

{
    echo "## Coastguard scan: $verdict"
    echo
    echo '```'
    echo "package: $nevra"
    echo "sha256:  $sha256"
    echo "files:   $file_count"
    echo "clamav:  $clam_hits detection(s)"
    echo "yara:    $yara_hits detection(s)"
    echo '```'
    if [ "$clam_hits" -gt 0 ]; then
        echo; echo '### ClamAV'; echo '```'; cat "$report/clamav-detections.txt"; echo '```'
    fi
    if [ "$yara_hits" -gt 0 ]; then
        echo; echo '### YARA'; echo '```'; cat "$report/yara-detections.txt"; echo '```'
    fi
    if [ ${#errors[@]} -gt 0 ]; then
        echo; echo '### Errors'; echo '```'; printf '%s\n' "${errors[@]}"; echo '```'
    fi
} > "$report/summary.md"

cat "$report/summary.md"
exit "$rc"
