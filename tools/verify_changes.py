"""Authoritative function-level diff between two ExportDecomp .c files.

The mnemonic-only match_functions.py is a weak first pass: it hashes instruction *mnemonics*
and so cannot see changed constants/operands. This instead compares the decompiled C of every
function with all relocation-dependent tokens masked (FUN_/DAT_/LAB_ names and flash/SRAM
absolute addresses), which catches changed immediates and control flow while ignoring the
address shifts that are an inevitable side effect of code growing between builds.

A function is "unchanged" if its fully-normalized C has an exact match somewhere in the other
image (alignment-free, so inserted/deleted functions don't cause false positives).

usage: verify_changes.py A.c B.c
"""
import collections
import re
import sys


def load(path):
    out = {}
    for blk in re.split(r'(?m)^(?=// ---- )', open(path).read()):
        m = re.match(r'// ---- (\S+) @ (\S+)', blk)
        if m:
            out[m.group(2)] = blk
    return out


def normalize(c):
    c = re.sub(r'(thunk_)?(FUN|DAT|LAB|UNK|PTR_DAT|PTR|switchD|caseD|joined_r)[_0-9a-fx]*', 'N', c)
    c = re.sub(r'0x0?800[0-9a-f]{3,}', 'A', c)   # flash code address (0x0800xxxx or 0x800xxxx)
    c = re.sub(r'0x2000[0-9a-f]{3,}', 'R', c)    # SRAM data address
    c = re.sub(r'// ---- .*', '', c)
    c = re.sub(r'@ \S+', '', c)
    return c.strip()


def main():
    a, b = load(sys.argv[1]), load(sys.argv[2])
    b_norm = collections.Counter(normalize(v) for v in b.values())
    changed = [(addr, blk.splitlines()[0].replace('// ---- ', ''))
               for addr, blk in a.items() if b_norm[normalize(blk)] == 0]
    print(f'{sys.argv[1]}: {len(a)} functions   {sys.argv[2]}: {len(b)} functions')
    print(f'unchanged (content match): {len(a) - len(changed)}')
    print(f'changed:                   {len(changed)}')
    for addr, hdr in sorted(changed):
        print(f'  {hdr}')


if __name__ == '__main__':
    main()
