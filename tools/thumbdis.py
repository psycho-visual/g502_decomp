"""Minimal Thumb-2 disassembler for the raw app image (base 0x08004000) with literal-pool
annotations. usage: thumbdis.py image.bin start_hex end_hex | --calls target_hex"""
import struct
import sys

import capstone

BASE = 0x08004000
img = open(sys.argv[1], 'rb').read()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
md.detail = True


def word(addr):
    o = addr - BASE
    return struct.unpack_from('<I', img, o)[0] if 0 <= o <= len(img) - 4 else None


def dis(start, end):
    for ins in md.disasm(img[start - BASE:end - BASE], start):
        note = ''
        if ins.mnemonic.startswith('ldr') and '[pc' in ins.op_str:
            for op in ins.operands:
                if op.type == capstone.arm.ARM_OP_MEM and op.mem.base == capstone.arm.ARM_REG_PC:
                    lit = ((ins.address + 4) & ~3) + op.mem.disp
                    v = word(lit)
                    note = f'   ; ={v:#010x}' if v is not None else ''
        yield ins, note


if sys.argv[2] == '--calls':
    tgt = int(sys.argv[3], 16)
    for ins, _ in dis(BASE, BASE + len(img)):
        if ins.mnemonic in ('bl', 'b.w', 'b') and ins.op_str == f'#{tgt:#x}':
            print(f'{ins.address:08x}: {ins.mnemonic} {ins.op_str}')
else:
    for ins, note in dis(int(sys.argv[2], 16), int(sys.argv[3], 16)):
        print(f'{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{note}')
