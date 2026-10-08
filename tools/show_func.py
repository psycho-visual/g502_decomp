"""Print the decompiled C of the named functions (or addresses) from an ExportDecomp .c file.
usage: show_func.py file.c NAME_OR_ADDR..."""
import re
import sys

text = open(sys.argv[1]).read()
parts = re.split(r'(?m)^(?=// ---- )', text)
want = [w.lower() for w in sys.argv[2:]]
for p in parts:
    m = re.match(r'// ---- (\S+) @ (\S+)', p)
    if m and (m.group(1).lower() in want or m.group(2).lower() in want):
        print(p.rstrip() + '\n')
