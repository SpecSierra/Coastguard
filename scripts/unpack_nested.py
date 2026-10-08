#!/usr/bin/env python3
"""Unpack what is packed inside an RPM payload, so the scanners see it.

usage: unpack_nested.py <payload-dir> <output-dir>

Two things are unpacked, recursively:
  - archives and compressed files (zip/jar/apk, tar, gzip, xz, bzip2, zstd,
    7z, cpio, rpm, deb), into <output-dir>/<path>.unpacked/
  - zlib streams embedded in ELF binaries and Qt .rcc files, which is where
    compiled-in Qt resources (QML, JavaScript) live, into
    <output-dir>/<path>.carved/

Nothing is executed. Size, count and depth are capped against archive bombs.
Prints a JSON summary on stdout.
"""
import bz2
import gzip
import json
import lzma
import mmap
import os
import re
import resource
import shutil
import stat
import subprocess
import sys
import zlib

MAX_DEPTH = 3
MAX_TOTAL = 2 * 1024**3       # everything unpacked, in bytes
MAX_FILE = 512 * 1024**2      # one unpacked file
MAX_ARCHIVES = 2000
MAX_CARVED_PER_FILE = 5000
CARVE_CAP = 32 * 1024**2      # one carved stream
CARVE_MIN = 64                # shorter streams are noise

MAGIC = [
    (0, b"PK\x03\x04", "zip"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"BZh", "bzip2"),
    (0, b"\x28\xb5\x2f\xfd", "zstd"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"\xed\xab\xee\xdb", "rpm"),
    (0, b"070701", "cpio"),
    (0, b"070702", "cpio"),
    (257, b"ustar", "tar"),
]
SINGLE = {"gzip": gzip.open, "xz": lzma.open, "bzip2": bz2.open}
ZLIB_HEADER = re.compile(rb"\x78[\x01\x5e\x9c\xda]")


def classify(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return None
    if head[:4] == b"\x7fELF" or head[:4] == b"qres":
        return "carve"
    # Static libraries are ar archives too; only Debian packages are worth opening.
    if head[:8] == b"!<arch>\n" and path.endswith((".deb", ".ipk", ".udeb")):
        return "ar"
    for offset, magic, kind in MAGIC:
        if head[offset:offset + len(magic)] == magic:
            return kind
    return None


def tree_size(root):
    total = files = 0
    for base, _, names in os.walk(root, followlinks=False):
        for name in names:
            try:
                st = os.lstat(os.path.join(base, name))
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
                files += 1
    return total, files


def extract(src, dest, kind, summary, label):
    """Returns True when something was unpacked into dest."""
    os.makedirs(dest, exist_ok=True)
    try:
        proc = subprocess.run(
            ["bsdtar", "-xf", src, "-C", dest, "--no-same-owner", "--no-same-permissions"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=180,
            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE)),
        )
        error = proc.stderr.decode("utf-8", "replace")
        failed = proc.returncode != 0
    except subprocess.TimeoutExpired:
        error, failed = "timed out", True
    subprocess.run(["chmod", "-R", "u+rwX", dest], check=False)

    if failed and re.search(r"passphrase|encrypt", error, re.I):
        # Scanners cannot see inside; worth telling the reader.
        summary["encrypted"].append(label)
    if failed and not os.listdir(dest) and kind in SINGLE:
        # A lone compressed file, not an archive.
        try:
            with SINGLE[kind](src, "rb") as fin, open(os.path.join(dest, "content"), "wb") as fout:
                written = 0
                while written < MAX_FILE:
                    block = fin.read(1 << 20)
                    if not block:
                        break
                    fout.write(block)
                    written += len(block)
            failed = False
        except (OSError, EOFError, lzma.LZMAError, zlib.error):
            pass
    if failed and len(summary["failed"]) < 50 and label not in summary["encrypted"]:
        summary["failed"].append(label)
    return bool(os.listdir(dest))


def carve(src, dest, summary):
    """Write out every complete zlib stream found in src."""
    count = 0
    try:
        fh = open(src, "rb")
    except OSError:
        return False
    with fh:
        if os.fstat(fh.fileno()).st_size < CARVE_MIN:
            return False
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
            size, resume = len(data), 0
            for match in ZLIB_HEADER.finditer(data):
                start = match.start()
                if start < resume:
                    continue
                inflater, out, pos = zlib.decompressobj(), bytearray(), start
                try:
                    while not inflater.eof and len(out) < CARVE_CAP and pos < size:
                        block = data[pos:pos + 65536]
                        pos += len(block)
                        while block and not inflater.eof and len(out) < CARVE_CAP:
                            out += inflater.decompress(block, CARVE_CAP - len(out))
                            block = inflater.unconsumed_tail
                except zlib.error:
                    continue
                # eof means the checksum matched, so this was a real stream.
                if not (inflater.eof or len(out) >= CARVE_CAP) or len(out) < CARVE_MIN:
                    continue
                if count == 0:
                    os.makedirs(dest, exist_ok=True)
                with open(os.path.join(dest, f"{start:08x}.bin"), "wb") as fout:
                    fout.write(out)
                resume = pos - len(inflater.unused_data)
                count += 1
                if count >= MAX_CARVED_PER_FILE:
                    summary["limits_hit"].add("carved streams per file")
                    break
    summary["carved_streams"] += count
    return count > 0


def main():
    payload, out_root = os.path.realpath(sys.argv[1]), os.path.realpath(sys.argv[2])
    summary = {"archives": 0, "carved_streams": 0, "files": 0, "bytes": 0,
               "encrypted": [], "failed": [], "limits_hit": set()}
    queue = [(payload, 0)]
    while queue:
        root, depth = queue.pop(0)
        for base, _, names in os.walk(root, followlinks=False):
            for name in sorted(names):
                src = os.path.join(base, name)
                try:
                    if not stat.S_ISREG(os.lstat(src).st_mode):
                        continue
                except OSError:
                    continue
                kind = classify(src)
                if kind is None:
                    continue
                if depth >= MAX_DEPTH:
                    summary["limits_hit"].add("nesting depth")
                    continue
                if summary["bytes"] >= MAX_TOTAL or summary["archives"] >= MAX_ARCHIVES:
                    summary["limits_hit"].add("total unpacked size or archive count")
                    continue
                if root == payload:
                    label = "/" + os.path.relpath(src, payload)
                    target = os.path.join(out_root, os.path.relpath(src, payload))
                else:
                    label = "nested/" + os.path.relpath(src, out_root)
                    target = src
                if kind == "carve":
                    dest = target + ".carved"
                    produced = carve(src, dest, summary)
                else:
                    dest = target + ".unpacked"
                    produced = extract(src, dest, kind, summary, label)
                    summary["archives"] += produced
                if not produced:
                    shutil.rmtree(dest, ignore_errors=True)
                    continue
                size, files = tree_size(dest)
                if summary["bytes"] + size > MAX_TOTAL:
                    shutil.rmtree(dest, ignore_errors=True)
                    summary["limits_hit"].add("total unpacked size or archive count")
                    continue
                summary["bytes"] += size
                summary["files"] += files
                queue.append((dest, depth + 1))
    summary["limits_hit"] = sorted(summary["limits_hit"])
    json.dump(summary, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
