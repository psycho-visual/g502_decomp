"""Pair up functions between two ExportDecomp.java exports and report what changed.

Functions are aligned in address order (the linker keeps the same layout between builds),
using the mnemonic-sequence hash to decide whether a pair is identical.
usage: match_functions.py A.functions.tsv B.functions.tsv
"""
import csv
import difflib
import sys


def load(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f, delimiter='\t'))


def main():
    a, b = load(sys.argv[1]), load(sys.argv[2])
    sm = difflib.SequenceMatcher(None, [r['mnem_sha1'] for r in a], [r['mnem_sha1'] for r in b],
                                 autojunk=False)
    same = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            same += i2 - i1
            continue
        for k in range(max(i2 - i1, j2 - j1)):
            ra = a[i1 + k] if i1 + k < i2 else None
            rb = b[j1 + k] if j1 + k < j2 else None
            fa = f"{ra['address']} {ra['name']} ({ra['ninsn']} insn)" if ra else '-'
            fb = f"{rb['address']} {rb['name']} ({rb['ninsn']} insn)" if rb else '-'
            print(f'{tag:8s} {fa:45s} -> {fb}')
    print(f'identical (by instruction sequence): {same} of {len(a)} / {len(b)}')


if __name__ == '__main__':
    main()
