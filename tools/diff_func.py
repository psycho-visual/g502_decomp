"""Unified diff of one function's decompiled C between two exports, with addresses masked.
usage: diff_func.py A.c addrA B.c addrB"""
import difflib
import re
import sys


def body(path, addr):
    text = open(path).read()
    for p in re.split(r'(?m)^(?=// ---- )', text):
        if re.match(rf'// ---- \S+ @ {addr}\b', p):
            return re.sub(r'\b(FUN|DAT|LAB|UNK|PTR)_[0-9a-f]{8}\b', r'\1_x', p).splitlines()
    sys.exit(f'{addr} not found in {path}')


a, b = body(sys.argv[1], sys.argv[2]), body(sys.argv[3], sys.argv[4])
sys.stdout.writelines(l + '\n' for l in difflib.unified_diff(a, b, sys.argv[2], sys.argv[4], n=2, lineterm=''))
