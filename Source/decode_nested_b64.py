#!/usr/bin/env python3
"""
Peel nested base64 layers WITHOUT executing anything.

Recognises:
  echo <b64> | base64 -d | sh
  printf %s <b64> | base64 --decode | bash
  <bare base64>
Writes the innermost plaintext to decoded_output.txt and never pipes it to a shell.

Usage:
  python3 decode_nested_b64.py payload.txt [-o out.txt] [--show N]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import re
import sys

MAX_LAYERS = 200
MAX_BYTES = 32 * 1024 * 1024

PIPE_RE = re.compile(
    r"""^\s*(?:echo|printf\s+(?:%s|['"]%s['"]))\s+
        (?P<q>['"]?)(?P<b64>[A-Za-z0-9+/=\s]{16,})(?P=q)\s*
        \|\s*base64\s+(?:-d|-D|--decode)\s*
        \|\s*(?:sh|bash|dash|zsh)\s*$""",
    re.X | re.S,
)
BARE_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def try_b64(data: bytes) -> bytes | None:
    """Decode base64 after removing all whitespace; None if it is not valid base64."""
    compact = re.sub(rb"\s+", b"", data)
    if not compact:
        return None
    if len(compact) % 4 == 1:
        return None
    compact += b"=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None


def textual(b: bytes) -> bool:
    if not b:
        return False
    try:
        b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    control = sum(1 for c in b if c < 0x09 or (0x0E <= c < 0x20) or c == 0x7F)
    return control / len(b) < 0.02


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default="decoded_output.txt")
    ap.add_argument("--show", type=int, default=40, help="lines of final text to print")
    args = ap.parse_args()

    raw = open(args.input, "rb").read(MAX_BYTES)
    cur = raw
    layers = []

    for depth in range(1, MAX_LAYERS + 1):
        text = cur.decode("utf-8", "replace")
        m = PIPE_RE.match(text)
        if m:
            encoded = m.group("b64").encode()
            kind = "echo|base64 -d|sh"
        elif BARE_RE.match(text) and len(text.strip()) >= 16:
            encoded = text.encode()
            kind = "bare base64"
        else:
            break

        nxt = try_b64(encoded)
        if nxt is None:
            print(f"[!] layer {depth}: {kind} but payload is not valid base64 - stopping")
            break

        layers.append(
            {
                "depth": depth,
                "kind": kind,
                "in": len(encoded),
                "out": len(nxt),
                "sha256": hashlib.sha256(nxt).hexdigest()[:16],
            }
        )
        cur = nxt
        if len(cur) > MAX_BYTES:
            print("[!] decoded data exceeded size cap - stopping")
            break
        if not textual(cur) and depth > 1:
            print(f"[i] layer {depth} decoded to binary data ({len(cur)} bytes) - stopping")
            break

    with open(args.output, "wb") as fh:
        fh.write(cur)

    print(f"{'depth':>5}  {'kind':<20}  {'in':>8}  {'out':>8}  sha256[:16]")
    for L in layers:
        print(f"{L['depth']:>5}  {L['kind']:<20}  {L['in']:>8}  {L['out']:>8}  {L['sha256']}")
    print(f"\nlayers peeled : {len(layers)}")
    print(f"final size    : {len(cur)} bytes")
    print(f"final sha256  : {hashlib.sha256(cur).hexdigest()}")
    print(f"written to    : {args.output}")

    if textual(cur):
        body = cur.decode("utf-8", "replace")
        lines = body.splitlines()
        print(f"\n----- first {min(args.show, len(lines))} of {len(lines)} lines -----")
        print("\n".join(lines[: args.show]))
    else:
        print("\n[i] final layer is binary; inspect the output file with xxd/file.")

    if re.search(r"\b(sh|bash)\b|\bcurl\b|\bwget\b|\bnc\b|\bbase64\b", cur.decode("utf-8", "ignore")):
        print("\n[!] final payload looks like shell script. Decoded, NOT executed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
