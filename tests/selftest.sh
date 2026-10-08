#!/usr/bin/env bash
# Prove the scanner can both pass and fail: build a harmless RPM and one
# carrying the EICAR test file, and check each gets the right verdict. A
# third package checks that the static inspection reports what it should.
#
# usage: selftest.sh <yara-rules> <clamav-db-dir>
set -euo pipefail

rules=$(realpath "$1")
clamdb=$(realpath "$2")
scan=$(dirname "$(realpath "$0")")/../scripts/scan.sh
top=$(mktemp -d)
trap 'rm -rf "$top"' EXIT
mkdir -p "$top/SOURCES" "$top/SPECS"
tree=$top/SOURCES/tree

build_rpm() { # <name> <%post body>; packages everything under $tree
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
cp -a %{_sourcedir}/tree/. %{buildroot}/
%post
$2
%files
/*
SPEC
    rpmbuild -bb --quiet --define "_topdir $top" "$top/SPECS/$1.spec" >&2
    rm -rf "$tree"
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

check() { # <report dir> <label> <jq filter that must be true>
    jq -e "$3" "$top/$1/report.json" > /dev/null \
        || { echo "FAIL: $2" >&2; jq . "$top/$1/report.json" >&2; exit 1; }
    echo "ok: $2"
}

# --- clean ------------------------------------------------------------------
mkdir -p "$tree/usr/share/coastguard-clean"
echo 'nothing to see here' > "$tree/usr/share/coastguard-clean/payload"
clean_rpm=$(build_rpm coastguard-clean 'true')
expect "clean package passes" 0 "$clean_rpm" "$top/report-clean"

# --- EICAR ------------------------------------------------------------------
mkdir -p "$tree/usr/share/coastguard-eicar"
# Assembled at runtime so this repository never contains the test file.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD' \
    '-ANTIVIRUS-TEST-FILE!$H+H*' > "$tree/usr/share/coastguard-eicar/payload"
eicar_rpm=$(build_rpm coastguard-eicar 'echo EICAR-STANDARD-ANTIVIRUS-TEST-FILE')
expect "EICAR package is detected" 1 "$eicar_rpm" "$top/report-eicar"
check report-eicar "ClamAV flags the payload" '.clamav | any(test("payload/.*FOUND$"))'
check report-eicar "YARA flags the payload"   '.yara | any(test(" payload/"))'
check report-eicar "YARA flags the scriptlet" '.yara | any(test(" scriptlets.txt$"))'

# --- inspection -------------------------------------------------------------
units=$tree/usr/lib/systemd/system
mkdir -p "$tree/usr/share/applications" "$tree/usr/share/cg/qml" \
    "$units/multi-user.target.wants" "$tree/etc/sudoers.d" "$tree/usr/bin"
printf '[Desktop Entry]\nName=Jailed\nExec=/usr/bin/cg\n\n[X-Sailjail]\nPermissions=Internet;Location\nOrganizationName=org.coastguard\nApplicationName=cg\n' \
    > "$tree/usr/share/applications/cg-jailed.desktop"
printf '[Desktop Entry]\nName=Open\nExec=/usr/bin/cg\n\n[X-Sailjail]\nSandboxing=Disabled\n' \
    > "$tree/usr/share/applications/cg-open.desktop"
printf '[Unit]\nDescription=test\n[Service]\nExecStart=/usr/bin/cg --daemon\n[Install]\nWantedBy=multi-user.target\n' \
    > "$units/cg.service"
ln -s ../cg.service "$units/multi-user.target.wants/cg.service"
echo 'fetch("https://telemetry.coastguard-selftest.io/v1"); fetch("http://203.0.113.7:8080/x")' \
    > "$tree/usr/share/cg/qml/main.qml"
echo 'nobody ALL=(ALL) NOPASSWD: ALL' > "$tree/etc/sudoers.d/cg"
printf '#!/bin/sh\ntrue\n' > "$tree/usr/bin/cg"
chmod 4755 "$tree/usr/bin/cg"
inspect_rpm=$(build_rpm coastguard-inspect 'systemctl enable cg.service')
expect "inspection package is not a detection" 0 "$inspect_rpm" "$top/report-inspect"
i=.inspect
check report-inspect "declared sandbox and its permissions" \
    "$i.sailjail.apps | any(.sandbox == \"declared\" and .permissions == [\"Internet\", \"Location\"])"
check report-inspect "disabled sandbox" "$i.sailjail.apps | any(.sandbox == \"disabled\")"
check report-inspect "root systemd service, enabled twice over" \
    "$i.services.systemd | any(.user == \"root\" and (.enabled_by | length) == 2)"
check report-inspect "setuid binary, and only that one" \
    "$i.privileged_files | map(.path) == [\"/usr/bin/cg\"]"
check report-inspect "sudoers drop-in" "$i.system_integration.sudoers == [\"/etc/sudoers.d/cg\"]"
check report-inspect "scriptlet command" "$i.scriptlets | any(.notable | any(test(\"systemctl\")))"
check report-inspect "host from QML" \
    "$i.network.hosts | any(.host == \"telemetry.coastguard-selftest.io\" and (.in | index(\"script\")))"
check report-inspect "hard-coded IP" "$i.network.notable | any(.why == \"hard-coded IP address\")"
echo "self-test passed"
