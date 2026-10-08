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

here=$(dirname "$(realpath "$0")")
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
version=$(rpm -qp --nosignature --qf '%{VERSION}-%{RELEASE}' "$rpm_file")
arch=$(rpm -qp --nosignature --qf '%{ARCH}' "$rpm_file")
# Orders the builds of a package when a later scan is compared with this one.
buildtime=$(rpm -qp --nosignature --qf '%{BUILDTIME}' "$rpm_file")
[[ $buildtime =~ ^[0-9]+$ ]] || buildtime=0

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

# Archives and compiled-in Qt resources inside the payload, unpacked so that
# YARA and the inspection see their content too.
mkdir "$work/nested"
if ! python3 -I "$here/unpack_nested.py" "$work/payload" "$work/nested" \
    > "$report/nested.json" 2> "$report/nested-error.log"; then
    echo '{"error": "nested unpacking failed, see nested-error.log"}' > "$report/nested.json"
    errors+=("nested unpacking failed")
fi
[ -s "$report/nested-error.log" ] || rm -f "$report/nested-error.log"
chmod -R u+rwX "$work/nested"

targets=("$rpm_file" "$work/payload" "$work/nested" "$work/scriptlets.txt")
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
: > "$work/yara.out"
: > "$work/yara.err"
if [ -d "$rules" ]; then rule_files=("$rules"/*.yar); else rule_files=("$rules"); fi
if yarac -w "${rule_files[@]}" "$work/rules.yarc" 2>> "$work/yara.err"; then
    for target in "${targets[@]}"; do
        # -N: do not follow symlinks out of the payload
        yara -C -r -N -w "$work/rules.yarc" "$target" 2>> "$work/yara.err" \
            | clean_paths >> "$work/yara.out" \
            || errors+=("yara failed on $(basename "$target")")
    done
else
    errors+=("could not compile YARA rules")
fi
if [ -s "$work/yara.err" ]; then
    clean_paths < "$work/yara.err" > "$report/yara-error.log"
fi
# Indicator rules describe capabilities and do not count towards the verdict
# (see rules/sailfish.yar).
grep '^Coastguard_Indicator_' "$work/yara.out" > "$report/yara-indicators.txt" || true
grep -v '^Coastguard_Indicator_' "$work/yara.out" > "$report/yara-detections.txt" || true
yara_hits=$(wc -l < "$report/yara-detections.txt")

# --- static inspection --------------------------------------------------------
# Informational: describes what the package sets up, never changes the verdict.
rpm -qp --nosignature --qf \
    '[%{FILEMODES:perms}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILECAPS}\t%{FILENAMES}\n]' \
    "$rpm_file" > "$work/filemeta.tsv" 2>/dev/null || true
if ! python3 -I "$here/inspect_rpm.py" "$work/payload" "$work/filemeta.tsv" \
    "$work/scriptlets.txt" "$report" "$work/nested" 2> "$report/inspect-error.log"; then
    echo '{"error": "inspection failed, see inspect-error.log"}' > "$report/inspect.json"
    printf '### What the package sets up\n\nInspection failed, see `inspect-error.log`.\n' \
        > "$report/inspect.md"
fi
[ -s "$report/inspect-error.log" ] || rm -f "$report/inspect-error.log"

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
    --arg name "$name" --arg version "$version" --arg arch "$arch" \
    --argjson buildtime "$buildtime" \
    --arg source "${RPM_URL:-}" --arg source_page "${APP_PAGE:-}" \
    --arg scanned "$(date -u +%FT%TZ)" \
    --arg yara_rules "${YARA_RULES_VERSION:-unknown}" \
    --arg clamav "$(clamscan --database="$clamdb" --version 2>/dev/null || true)" \
    --argjson files "$file_count" \
    --rawfile clam "$report/clamav-detections.txt" \
    --rawfile yara "$report/yara-detections.txt" \
    --rawfile indicators "$report/yara-indicators.txt" \
    --slurpfile nested "$report/nested.json" \
    --slurpfile inspect "$report/inspect.json" \
    --args '{
        verdict: $verdict, name: $name, version: $version, arch: $arch,
        package: $package, buildtime: $buildtime, sha256: $sha256,
        source: $source, source_page: $source_page,
        scanned: $scanned, files: $files,
        engines: {clamav: $clamav, yara_forge_core: $yara_rules},
        clamav: ($clam | split("\n") | map(select(. != ""))),
        yara: ($yara | split("\n") | map(select(. != ""))),
        indicators: ($indicators | split("\n")
            | map(select(. != "") | capture("^(?<rule>\\S+) (?<file>.*)$"))
            | group_by(.rule) | map({rule: .[0].rule, files: (map(.file) | unique)})),
        errors: $ARGS.positional,
        nested: $nested[0],
        inspect: $inspect[0]
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
    echo
    echo '### Indicators'
    echo
    echo 'Things the package is able to do that deserve a look. Legitimate apps match these too; they do not change the verdict.'
    echo
    jq -r 'if (.indicators | length) == 0 then "None." else .indicators[]
        | "- " + (.rule | sub("^Coastguard_Indicator_"; "") | gsub("_"; " ")) + ": "
          + (.files[:4] | map("`" + gsub("[`|]"; " ") + "`") | join(", "))
          + (if (.files | length) > 4 then " (+\((.files | length) - 4) more)" else "" end)
        end' "$report/report.json"
    echo
    jq -r '.nested | if .error then "Nested content: " + .error else
        "Nested content: \(.archives) archive(s) and \(.carved_streams) embedded compressed stream(s) unpacked and scanned (\(.files) files)."
        + (if (.encrypted | length) > 0 then " :warning: Password-protected, not scannable: " + (.encrypted | map("`" + gsub("[`|]"; " ") + "`") | join(", ")) + "." else "" end)
        + (if (.limits_hit | length) > 0 then " :warning: Limits hit, content skipped: " + (.limits_hit | join(", ")) + "." else "" end)
        end' "$report/report.json"
    echo; cat "$report/inspect.md"
} > "$report/summary.md"

cat "$report/summary.md"
exit "$rc"
