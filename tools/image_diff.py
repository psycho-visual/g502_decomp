"""Whole-image, relocation-aware diff of two raw app images (base 0x08004000).

verify_changes.py only compares what Ghidra recognised as functions (~58% of each image), so
it is blind to code reached only through pointer tables (e.g. the HID++ feature handlers) and
to data. This tool needs no function list:

  1. recursive-descent disassembly (Thumb-2) from every code pointer in the image (vector
     table, handler tables: any aligned word = odd address inside the image) plus, if given,
     Ghidra's function starts; follows branches, calls and TBB/TBH tables, and marks every
     word loaded with `ldr rX, [pc, #n]` as a literal
  2. code becomes one token per instruction with relocation-dependent parts masked (branch
     targets, PC-relative offsets, literal values pointing into flash/SRAM); everything
     else is data, one token per aligned word, flash/SRAM pointers masked
  3. difflib aligns the two token streams; every non-equal block is printed with its
     address range in both images and the Ghidra function containing it (if any)

usage: image_diff.py A.bin B.bin [A.functions.tsv B.functions.tsv]
"""
import difflib
import re
import struct
import sys

import capstone
from capstone.arm import (ARM_CC_AL, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_LR,
                          ARM_REG_PC)

BASE = 0x08004000
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
md.detail = True


def norm_word(v):
    if 0x08000000 <= v < 0x08020000:
        return 'A'                      # flash address (code/const), relocates between builds
    if 0x20000000 <= v < 0x20004000:
        return 'R'                      # SRAM address, relocates between builds
    return f'{v:#x}'


class Image:
    def __init__(self, img, extra_entries=()):
        self.img = img
        self.end = BASE + len(img)
        self.code = {}                  # addr -> CsInsn
        self.lit = set()
        self.data_tbl = set()           # bytes of TBB/TBH tables
        entries = set(extra_entries)
        for off in range(0, len(img) - 3, 4):
            w = struct.unpack_from('<I', img, off)[0]
            if w & 1 and BASE <= w - 1 < self.end:
                entries.add(w - 1)
        self._walk(entries)

    def _insn(self, addr):
        off = addr - BASE
        return next(md.disasm(self.img[off:off + 4], addr, count=1), None)

    def _walk(self, entries):
        work = list(entries)
        while work:
            addr = work.pop()
            while BASE <= addr < self.end and addr not in self.code and addr not in self.lit:
                ins = self._insn(addr)
                if ins is None:
                    break
                self.code[addr] = ins
                nxt = addr + ins.size
                m, ops = ins.mnemonic, ins.operands
                if m.startswith('ldr') and '[pc' in ins.op_str:
                    for op in ops:
                        if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                            a = ((addr + 4) & ~3) + op.mem.disp
                            self.lit.update((a, a + 1, a + 2, a + 3))
                    if ops[0].type == ARM_OP_REG and ops[0].reg == ARM_REG_PC:
                        break
                if m in ('tbb', 'tbh'):
                    n = self._table_len(addr)
                    w = 1 if m == 'tbb' else 2
                    tbl = addr + 4
                    for i in range(n):
                        o = tbl - BASE + i * w
                        off = self.img[o] if w == 1 else struct.unpack_from('<H', self.img, o)[0]
                        work.append(tbl + 2 * off)
                    self.data_tbl.update(range(tbl, tbl + n * w))
                    break
                if m in ('b', 'b.w', 'bl', 'cbz', 'cbnz') or (m.startswith('b') and len(ops) == 1
                                                              and ops[0].type == ARM_OP_IMM):
                    work.append(ops[0].imm if m not in ('cbz', 'cbnz') else ops[1].imm)
                    if m in ('b', 'b.w') and ins.cc in (ARM_CC_AL, 0) and not self._in_it(addr):
                        break
                if m in ('bx', 'blx') and ops[0].type == ARM_OP_REG and m == 'bx':
                    break
                if m.startswith('pop') and any(o.reg == ARM_REG_PC for o in ops):
                    if not self._in_it(addr):
                        break
                if ops and ops[0].type == ARM_OP_REG and ops[0].reg == ARM_REG_PC and \
                        m.startswith(('mov', 'ldm', 'add')):
                    break
                addr = nxt

    def _in_it(self, addr):
        for back in (2, 4, 6, 8):
            p = self.code.get(addr - back)
            if p is not None and p.mnemonic.startswith('it'):
                return True
        return False

    def _table_len(self, addr):
        for back in range(2, 14, 2):
            p = self.code.get(addr - back)
            if p is not None and p.mnemonic == 'cmp' and p.operands[1].type == ARM_OP_IMM:
                return p.operands[1].imm + 1
        return 1

    def tokens(self):
        out, a = [], BASE
        while a < self.end:
            ins = self.code.get(a)
            if ins is not None and a not in self.lit:
                ops = ins.op_str
                if ins.mnemonic.startswith(('b', 'cb')) and not ins.mnemonic.startswith('bic'):
                    ops = re.sub(r'#0x[0-9a-f]+', 'T', ops)
                elif '[pc' in ops or ins.mnemonic.startswith('adr'):
                    ops = re.sub(r'#-?0x[0-9a-f]+|#-?\d+', 'P', ops)
                out.append((a, f'{ins.mnemonic} {ops}'))
                a += ins.size
                continue
            if a in self.data_tbl:
                out.append((a, f'.tbl {self.img[a - BASE]:#04x}'))
                a += 1
                continue
            if not a & 3 and a + 4 <= self.end:
                w = struct.unpack_from('<I', self.img, a - BASE)[0]
                out.append((a, ('LIT ' if a in self.lit else '.word ') + norm_word(w)))
                a += 4
                continue
            if a & 1 or a + 2 > self.end:
                out.append((a, f'.byte {self.img[a - BASE]:#04x}'))
                a += 1
                continue
            out.append((a, f'.short {struct.unpack_from("<H", self.img, a - BASE)[0]:#06x}'))
            a += 2
        return out


def load_funcs(path):
    funcs = []
    for line in open(path):
        f = line.rstrip('\n').split('\t')
        if re.fullmatch(r'[0-9a-f]{8}', f[0]):
            funcs.append((int(f[0], 16), int(f[2]), f[1]))
    return funcs


def where(funcs, img, addr):
    for a, sz, name in funcs:
        if a <= addr < a + sz:
            return name
    return 'code, not a Ghidra function' if addr in img.code else 'data'


def main():
    a_img, b_img = (open(p, 'rb').read() for p in sys.argv[1:3])
    fa = load_funcs(sys.argv[3]) if len(sys.argv) > 4 else []
    fb = load_funcs(sys.argv[4]) if len(sys.argv) > 4 else []
    ia = Image(a_img, [a for a, _, _ in fa])
    ib = Image(b_img, [a for a, _, _ in fb])
    for name, im in (('A', ia), ('B', ib)):
        print(f'{name}: {len(im.code)} instructions, '
              f'{sum(i.size for i in im.code.values()):#x} code bytes, {len(im.lit) // 4} literals')
    ta, tb = ia.tokens(), ib.tokens()
    sm = difflib.SequenceMatcher(None, [t for _, t in ta], [t for _, t in tb], autojunk=False)
    blocks = [op for op in sm.get_opcodes() if op[0] != 'equal']
    print(f'{len(ta)} / {len(tb)} tokens, {len(blocks)} differing blocks')
    for tag, i1, i2, j1, j2 in blocks:
        a0 = ta[i1][0] if i1 < len(ta) else ia.end
        b0 = tb[j1][0] if j1 < len(tb) else ib.end
        print(f'\n{tag:7s} A {a0:08x} +{i2 - i1:<3d} [{where(fa, ia, a0)}]   '
              f'B {b0:08x} +{j2 - j1:<3d} [{where(fb, ib, b0)}]')
        for k in range(max(i2 - i1, j2 - j1)):
            if k == 12:
                print('    ...')
                break
            l = f'{ta[i1 + k][0]:08x}: {ta[i1 + k][1]}' if i1 + k < i2 else ''
            r = f'{tb[j1 + k][0]:08x}: {tb[j1 + k][1]}' if j1 + k < j2 else ''
            print(f'    {l:46s} | {r}')


if __name__ == '__main__':
    main()
