# `silisili-native-devel-1.1.0-1.59.aarch64`: high risk

### Risk grade: high: review before installing

- :rotating_light: Root service and no sandbox (`root-service-no-sandbox`)
- :warning: Sandbox turned off (`sandbox-off`)
- :warning: 1 root service, started at install (`root-services`)
- :warning: System hook: privileged launcher grant (`hook-privileged-launcher-grant`)

The grade describes how much the package gets to do on the device, from what it declares and installs. It is a set of heuristics, not a verdict. A flag is a prompt to explain, not an accusation: developers can answer each one by its id, see [Explaining a flag](https://github.com/SpecSierra/Coastguard#explaining-a-flag).

### Changes since `silisili-native-devel-1.1.0-1.58.aarch64`

**Files**: 0 added, 0 removed, 1 changed, 28 unchanged

- changed: `/usr/bin/silisili-native`

**Hosts**: 0 added, 0 removed

### What the package sets up (static inspection)

**Sailjail sandbox**

- `/usr/share/applications/cn.silisili.native.desktop`: :warning: sandbox explicitly disabled (`Sandboxing=Disabled`); runs `/usr/bin/silisili-native`

**Services and autostart**

- systemd system unit `/usr/lib/systemd/system/silisili-native-minimedia.service` as `root`: `/usr/libexec/silisili-native/silisili-native-minimedia-wrapper` (enabled or started from an install scriptlet)

**Privileges and system hooks**

- privileged launcher grant: `/usr/share/mapplauncherd/privileges.d/silisili-native`

**Install scriptlets (run as root)**

- `postinstall`: 25 line(s), 10 worth reading:
  - `native_dir=/home/defaultuser/.config/cn.silisili.native`
  - `stable_config=/home/defaultuser/.config/silisili/silisili_config.json`
  - `legacy_snapshot=/home/defaultuser/.config/silisili-native/stable_config_snapshot.json`
  - `chmod 700 "$native_dir" || :`
  - `chown defaultuser:defaultuser "$native_dir" 2>/dev/null || chown defaultuser "$native_dir" 2>/dev/null || :`
  - `chmod 600 "$native_snapshot" || :`
  - `chown defaultuser:defaultuser "$native_snapshot" 2>/dev/null || chown defaultuser "$native_snapshot" 2>/dev/null || :`
  - `systemctl daemon-reload >/dev/null 2>&1 || :`
  - `systemctl enable silisili-native-minimedia.service >/dev/null 2>&1 || :`
  - `systemctl restart silisili-native-minimedia.service >/dev/null 2>&1 || :`
- `preuninstall`: 4 line(s), 1 worth reading:
  - `systemctl disable --now silisili-native-minimedia.service >/dev/null 2>&1 || :`
- `postuninstall`: 2 line(s), 1 worth reading:
  - `systemctl daemon-reload >/dev/null 2>&1 || :`

**Embedded addresses**

Addresses written in the package's files, not a record of what the app contacts. Addresses built at runtime do not show up here.

- in its scripts and config: `fsf.org`, `www.nayuki.io`
- in its binaries: `curl.se`, `www.bilibili.com`, `0x0.st`, `ffmpeg.org`, `github.com`, `live.bilibili.com`, `message.bilibili.com`, `search.bilibili.com`, `space.bilibili.com`, `streams.videolan.org`, `t.bilibili.com`

---

Known-malware check (ClamAV, YARA, VirusTotal, MalwareBazaar): nothing recognised. This only covers malware that is already catalogued.

| | |
|---|---|
| Scanned | 2026-10-14T02:38:35Z |
| sha256 | `545bb815c0dcfcbfdae6b0ab36ab7d55bbfd35f4ebbbb2408319269fbd45dddb` |
| Source | `https://openrepos.net/sites/default/files/packages/19602/silisili-native-devel-1.1.0-1.59.aarch64.rpm` |

Automatic report by [Coastguard](https://github.com/SpecSierra/Coastguard). It describes what a package gets to do on a device; it is not a guarantee that the package is safe.
