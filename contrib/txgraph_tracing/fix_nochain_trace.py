#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fix nochain trace: remove duplicate START_STAGING before COMMIT.

The buggy rewrite output had: START_STAGING, mutations, START_STAGING (dup),
extra ADD_DEPs, COMMIT_STAGING. This causes replay to assert. We remove the
duplicate START_STAGING when we see it while already in a staging block.

Usage:
    python3 fix_nochain_trace.py <buggy_trace> <fixed_trace>
"""

import struct
import sys

START_STAGING = 0x20
ABORT_STAGING = 0x21
COMMIT_STAGING = 0x22

FIXED_PAYLOAD = {
    0x00: 20, 0x01: 16, 0x02: 4, 0x03: 8, 0x04: 12, 0x05: 4,
    0x10: 0, 0x11: 8, 0x12: 8, 0x13: 5, 0x14: 5, 0x17: 5, 0x18: 4,
    0x1a: 0, 0x1b: 0, 0x1c: 0, 0x1d: 0, 0x1e: 1, 0x1f: 5,
    0x20: 0, 0x21: 0, 0x22: 0, 0x23: 4, 0x24: 1,
}
VAR_LENGTH_OPS = {0x15, 0x16, 0x19}


def read_var_payload(f):
    raw = f.read(4)
    if len(raw) < 4:
        return None
    count = struct.unpack('<I', raw)[0]
    return raw + f.read(count * 4 + 1) if count <= 0x100000 else None


def main():
    if len(sys.argv) != 3:
        print("Usage: fix_nochain_trace.py <buggy_trace> <fixed_trace>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], 'rb') as fin, open(sys.argv[2], 'wb') as fout:
        fout.write(fin.read(12))
        in_staging = False
        skipped = 0

        while True:
            b = fin.read(1)
            if not b:
                break
            op = b[0]

            if op in VAR_LENGTH_OPS:
                payload = read_var_payload(fin)
                if payload is None:
                    break
                fout.write(b)
                fout.write(payload)
                continue

            psize = FIXED_PAYLOAD.get(op, -1)
            if psize < 0:
                break
            raw = fin.read(psize) if psize else b''
            if len(raw) < psize:
                break

            if op == START_STAGING:
                if in_staging:
                    skipped += 1
                    continue
                in_staging = True
            elif op in (COMMIT_STAGING, ABORT_STAGING):
                in_staging = False

            fout.write(b)
            fout.write(raw)

    print(f"Fixed: skipped {skipped} duplicate START_STAGING")


if __name__ == '__main__':
    main()
