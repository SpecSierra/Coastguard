# `felis-phone-start-page-1.0.0-3.noarch`: low risk

### Risk grade: low: nothing unusual

- System hook: system UI patches (`hook-system-ui-patches`)

The grade describes how much the package gets to do on the device, from what it declares and installs. It is a set of heuristics, not a verdict. A flag is a prompt to explain, not an accusation: developers can answer each one by its id, see [Explaining a flag](https://github.com/SpecSierra/Coastguard#explaining-a-flag).

### Changes since the previous version

No earlier build of this package has been scanned, so there is nothing to compare with.

### What the package sets up (static inspection)

**Sailjail sandbox**

No launcher (`.desktop`) entry: nothing here is started as a sandboxed app.

**Services and autostart**

None.

**Privileges and system hooks**

- system UI patches: `/usr/share/patchmanager/patches/felis-phone-start-page/main.qml`, `/usr/share/patchmanager/patches/felis-phone-start-page/patch.json`, `/usr/share/patchmanager/patches/felis-phone-start-page/unified_diff.patch`

**Install scriptlets (run as root)**

- `preinstall`: 3 line(s)
- `preuninstall`: 3 line(s)

**Embedded addresses**

Addresses written in the package's files, not a record of what the app contacts. Addresses built at runtime do not show up here.

None found.

---

Known-malware check (ClamAV, YARA, VirusTotal, MalwareBazaar): nothing recognised. This only covers malware that is already catalogued.

| | |
|---|---|
| Scanned | 2026-10-14T07:23:38Z |
| sha256 | `3e4dd15b4ffdcff7c22926f0c1ff7b8b18d6765b66aebb08b6e8fb7fd3f1a5ec` |
| Source | `https://openrepos.net/sites/default/files/packages/19742/felis-phone-start-page-1.0.0-3.noarch.rpm` |

Automatic report by [Coastguard](https://github.com/SpecSierra/Coastguard). It describes what a package gets to do on a device; it is not a guarantee that the package is safe.
