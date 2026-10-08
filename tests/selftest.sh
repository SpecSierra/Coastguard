#!/usr/bin/env bash
# Prove the scanner can both pass and fail: build a harmless RPM and one
# carrying the EICAR test file, and check each gets the right verdict.
#
# usage: selftest.sh <yara-rules> <clamav-db-dir>
set -euo pipefail

rules=$(realpath "$1")
clamdb=$(realpath "$2")
scan=$(dirname "$(realpath "$0")")/../scripts/scan.sh
top=$(mktemp -d)
trap 'rm -rf "$top"' EXIT
mkdir -p "$top/SOURCES" "$top/SPECS"

build_rpm() { # <name> <%post body>; payload is $top/SOURCES/payload
    cat > "$top/SPECS/$1.spec" <<SPEC
Name: $1
Version: 1
Release: 1
Summary: Coastguard self-test package
License: Public Domain
BuildArch: noarch
%description
Coastguard self-test package.
%install
install -D -m 644 %{_sourcedir}/payload %{buildroot}/usr/share/$1/payload
%post
$2
%files
/usr/share/$1/payload
SPEC
    rpmbuild -bb --quiet --define "_topdir $top" "$top/SPECS/$1.spec" >&2
    echo "$top/RPMS/noarch/$1-1-1.noarch.rpm"
}

expect() { # <label> <expected rc> <rpm> <report dir>
    local rc=0
    "$scan" "$3" "$rules" "$clamdb" "$4" || rc=$?
    if [ "$rc" -ne "$2" ]; then
        echo "FAIL: $1: expected exit $2, got $rc" >&2
        exit 1
    fi
    echo "ok: $1 (exit $rc)"
}

echo 'nothing to see here' > "$top/SOURCES/payload"
clean_rpm=$(build_rpm coastguard-clean 'true')
expect "clean package passes" 0 "$clean_rpm" "$top/report-clean"

# Assembled at runtime so this repository never contains the test file.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD' \
    '-ANTIVIRUS-TEST-FILE!$H+H*' > "$top/SOURCES/payload"
eicar_rpm=$(build_rpm coastguard-eicar 'echo EICAR-STANDARD-ANTIVIRUS-TEST-FILE')
expect "EICAR package is detected" 1 "$eicar_rpm" "$top/report-eicar"

check() { # <label> <jq filter that must be true>
    jq -e "$2" "$top/report-eicar/report.json" > /dev/null \
        || { echo "FAIL: $1" >&2; cat "$top/report-eicar/report.json" >&2; exit 1; }
    echo "ok: $1"
}
check "ClamAV flags the payload" '.clamav | any(test("payload/.*FOUND$"))'
check "YARA flags the payload"   '.yara | any(test(" payload/"))'
check "YARA flags the scriptlet" '.yara | any(test(" scriptlets.txt$"))'
echo "self-test passed"
