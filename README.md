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

Content packed inside the payload is unpacked and scanned as well: archives
(zip/jar/apk, tar, gzip, xz, bzip2, zstd, 7z, cpio, rpm, deb), up to three
levels deep, and zlib streams embedded in ELF binaries and Qt `.rcc` files,
which is where compiled-in QML and JavaScript live. Password-protected
archives cannot be opened and are called out in the report.

Two more checks run after the scan, in a job that only sees the report:

- **Hash reputation**: the sha256 of the RPM and of its executables is looked
  up on VirusTotal and MalwareBazaar. Only hashes are sent. A file that three
  or more VirusTotal engines call malicious, or that MalwareBazaar knows,
  turns the verdict to detected.
- **Changes since the previous version**: see below.

Each report also describes, from the files alone, what the package would set
up on a device. This is informational and never changes the verdict:

- **Sailjail**: for every launcher entry, whether a sandbox profile is
  declared, which permissions it asks for, or whether sandboxing is disabled;
  plus any sandbox profile files the package ships itself
- **Services**: systemd units (user, command, whether the package enables
  them), D-Bus activation files, autostart entries
- **Privileges and hooks**: setuid/setgid files, file capabilities, sudoers,
  polkit, udev, cron, package repositories and similar
- **Install scriptlets**: the commands worth reading
- **Network**: hosts and URLs embedded in the files, those in readable
  scripts/QML listed first, with hard-coded IPs and paste/tunnel/webhook
  services called out

## Watching OpenRepos

The `Watch OpenRepos` workflow runs every hour. It reads the OpenRepos app
listing, visits the page of each app updated since the last run, and starts a
scan for every RPM uploaded with that update, all architectures included. At
most 5 scans are started in any 60 minutes (`INTAKE_MAX_SCANS` in
`.github/workflows/intake.yml`); the rest wait in a queue. Scans run one at a time: each
starts only once the previous one has finished.

Only releases made after the watch started are scanned; the existing
catalogue is not backfilled. The watch position, the queue and the list of
URLs already handled are in `intake/state.json` on the `results` branch.

GitHub may start scheduled workflows late, and disables them after 60 days
without activity in the repository.

## Running a scan

    gh workflow run scan.yml -f rpm_url=https://openrepos.net/sites/default/files/packages/<uid>/<file>.rpm

Optionally add `-f sha256=<hash>` to pin the exact file.

The job passes when the package is clean, fails when something is detected or
when the scan could not complete. The verdict is in the run summary; the
`coastguard-report` artifact holds `report.json` and the raw logs.

## Results

Every clean or detected verdict is stored on the
[`results`](../../tree/results) branch, per package:

    packages/<name>/index.json              every scanned build, oldest first
    packages/<name>/<sha256>.json           the full result
    packages/<name>/<sha256>.manifest.tsv   sha256, size, kind, path per file

Rescanning the same file replaces its entry; the branch history keeps the
earlier ones. To look a file up by hash:

    git ls-tree -r --name-only origin/results | grep <sha256>

## Changes since the previous version

Each result is compared with the stored result of the build before it (by
RPM build time, same architecture when there is one). The comparison uses
the stored result, not the old RPM, so it keeps working after a developer
deletes the old version from OpenRepos.

Reported as worth reviewing: new permissions, a sandbox that was dropped, new
or changed services, new setuid files or system hooks, new scriptlet lines,
new indicators, and new hosts in scripts. Files added, removed and changed
are listed by path; the content of a changed file is not compared.

A build is only a baseline once Coastguard has scanned it, so the first scan
of a package has nothing to compare with.

## Reputation API keys

Both lookups are skipped until their key is added as a repository secret:

    gh secret set VT_API_KEY                # virustotal.com, free account
    gh secret set MALWAREBAZAAR_AUTH_KEY    # auth.abuse.ch, free account

The free VirusTotal tier allows 4 lookups a minute and 500 a day, so a scan
looks up the RPM and its 7 most relevant executables (`VT_MAX_FILES`).

## Rules and self-test

`rules/` holds Coastguard's own YARA rules, loaded next to the YARA Forge
set. `rules/sailfish.yar` has Sailfish OS specific **indicators**: reading the
contacts, message or account databases, touching SSH keys, calling `devel-su`,
editing sudoers, installing packages at runtime, download-and-run shell
lines, sending SMS, and so on. Legitimate apps match these too, so they are
listed in the report and in the version comparison but do not change the
verdict. A rule becomes a detection by dropping the `Coastguard_Indicator_`
prefix from its name.
 The `Self-test` workflow builds a harmless RPM and one carrying the
EICAR test file on every push, and checks that the first passes and the
second is flagged by both engines. Further packages check nested unpacking,
the inspection, the indicators and the version comparison.

## Limits

A clean result means "no known signature matched", not "safe". Signature
scanning does not catch new or targeted malware. Niche Sailfish packages are
mostly unknown to the reputation services, where "unknown" is not a pass.

The inspection is static. The network list is what is written in the files,
not what the app contacts: addresses built at runtime, obfuscated or stored
in compressed resources are missed, and a large binary carries many hosts it
never talks to.
