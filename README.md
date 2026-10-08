# Coastguard

A tool for safe sailing: malware scanning for Sailfish OS packages published
on OpenRepos.

## What it does today

The `Scan RPM` workflow downloads one RPM and checks it with:

- **ClamAV**, using the official signature database (refreshed daily)
- **YARA**, using the [YARA Forge](https://yarahq.github.io/) *core* rule set

The scan covers the RPM itself, every file in its payload, and its install
scriptlets (`%pre`, `%post`, triggers), which run as root on the device. The
package is only unpacked, never installed or executed.

## Running a scan

    gh workflow run scan.yml -f rpm_url=https://openrepos.net/sites/default/files/packages/<uid>/<file>.rpm

Optionally add `-f sha256=<hash>` to pin the exact file.

The job passes when the package is clean, fails when something is detected or
when the scan could not complete. The verdict is in the run summary; the
`coastguard-report` artifact holds `report.json` and the raw logs.

## Results

Every clean or detected verdict is stored on the
[`results`](../../tree/results) branch as `packages/<name>/<sha256>.json`.
Rescanning the same file replaces its entry; the branch history keeps the
earlier ones. To look a file up by hash:

    git ls-tree -r --name-only origin/results | grep <sha256>

## Rules and self-test

`rules/` holds Coastguard's own YARA rules, loaded next to the YARA Forge
set. The `Self-test` workflow builds a harmless RPM and one carrying the
EICAR test file on every push, and checks that the first passes and the
second is flagged by both engines.

## Limits

A clean result means "no known signature matched", not "safe". Signature
scanning does not catch new or targeted malware, and YARA does not look inside
archives nested in the payload (ClamAV does).
