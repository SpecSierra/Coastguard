# `harbour-foilpics-1.1.8-1.i486`: medium risk

### Risk grade: medium: worth a look

- :warning: Sandbox turned off (`sandbox-off`)

The grade describes how much the package gets to do on the device, from what it declares and installs. It is a set of heuristics, not a verdict. A flag is a prompt to explain, not an accusation: developers can answer each one by its id, see [Explaining a flag](https://github.com/SpecSierra/Coastguard#explaining-a-flag).

### Changes since the previous version

No earlier build of this package has been scanned, so there is nothing to compare with.

### What the package sets up (static inspection)

**Sailjail sandbox**

- `/usr/share/applications/harbour-foilpics.desktop`: :warning: sandbox explicitly disabled (`Sandboxing=Disabled`); runs `harbour-foilpics`

**Services and autostart**

None.

**Privileges and system hooks**

No setuid/setgid files, file capabilities or system hooks.

**Install scriptlets (run as root)**

None.

**Embedded addresses**

Addresses written in the package's files, not a record of what the app contacts. Addresses built at runtime do not show up here.

- in its scripts and config: `github.com`, `openrepos.net`

---

Known-malware check (ClamAV, YARA, VirusTotal, MalwareBazaar): nothing recognised. This only covers malware that is already catalogued.

| | |
|---|---|
| Scanned | 2026-10-19T23:20:44Z |
| sha256 | `c2c89bccbcd7e5939d520ffbcb4cffc5d9e885d85da0ad7acd18f3c2d872ee4d` |
| Source | `https://openrepos.net/sites/default/files/packages/7548/harbour-foilpics-1.1.8-1.i486.rpm` |

Automatic report by [Coastguard](https://github.com/SpecSierra/Coastguard). It describes what a package gets to do on a device; it is not a guarantee that the package is safe.
