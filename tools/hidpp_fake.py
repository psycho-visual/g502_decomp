"""Offline test for hidpp_version.py: a fake `hid` module that answers HID++ like a G502 HERO
running a given app image.

HID++ 0x0003 (getDeviceInfo / getFwInfo) is answered by running the image's own handlers
under Unicorn; Root (0x0000), FeatureSet (0x0001) and DeviceName (0x0005) are synthesised
from the feature table read out of the same image. Things that live outside the app image
are placeholders: the STM32 unique ID (unitId), the factory EEPROM byte behind
extendedModelId (left blank -> firmware reports 0) and the bootloader's build digits at
0x08003FF6 (set to "0000" -> BOT build B0000 here; real units will differ).

usage: hidpp_fake.py APP.bin [hidpp_version.py options]
"""
import os
import struct
import sys
import types

from unicorn import UC_ARCH_ARM, UC_MODE_MCLASS, UC_MODE_THUMB, Uc
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP

BASE = 0x08004000
RET = 0x08000100


class G502:
    def __init__(self, path):
        img = self.img = open(path, 'rb').read()
        mu = self.mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        mu.mem_map(0x08000000, 0x10000)
        mu.mem_write(BASE, img)
        mu.mem_write(0x08003FF4, b'B\x000\x000\x000\x000\x00')   # placeholder bootloader build
        mu.mem_map(0x08080000, 0x1000)                           # data EEPROM (blank)
        mu.mem_map(0x1FF80000, 0x1000)
        mu.mem_write(0x1FF80050, struct.pack('<I', 0x12345678))  # placeholder unique ID
        mu.mem_map(0x20000000, 0x4000)
        self.features = self._feature_table()
        self.idx0003 = next(i for i, f in enumerate(self.features) if f[0] == 0x0003)
        functab = self.features[self.idx0003][3]
        self.h_devinfo, self.h_fwinfo = struct.unpack('<II', self._rd(functab, 8))
        ver = img[img.find(b'U127.'):][:13]
        self.build_init = {b'U127.01_B0007': 0x0800af40, b'U127.03_B0010': 0x0800b124}[ver]
        self._call(self.build_init)                               # writes the BCD build to RAM
        self.name = b'G502 HERO Gaming Mouse'

    def _rd(self, addr, n):
        return bytes(self.mu.mem_read(addr, n))

    def _feature_table(self):
        """The array of feature-record pointers: [(id, flags, version, functable)].
        Record layout: u16 id, u8 flags, u8 version, u32, u32 -> handler table."""
        img = self.img
        def rec(p):
            o = p - BASE
            if not (0 <= o < len(img) - 12):
                return None
            fid, fl, ver, _, ft = struct.unpack_from('<HBBII', img, o)
            return fid, fl, ver, ft
        for off in range(0, len(img) - 64, 4):
            ptrs = struct.unpack_from('<16I', img, off)
            recs = [rec(p) for p in ptrs]
            if all(recs) and recs[0][0] == 0x0003 and any(r[0] == 0x2201 for r in recs):
                return [(0x0000, 0, 0, 0), (0x0001, 0, 0, 0)] + recs
        raise RuntimeError('feature table not found')

    def _call(self, fn, r0=0, r1=0):
        mu = self.mu
        mu.reg_write(UC_ARM_REG_SP, 0x20003F00)
        mu.reg_write(UC_ARM_REG_LR, RET | 1)
        mu.reg_write(UC_ARM_REG_R0, r0)
        mu.reg_write(UC_ARM_REG_R1, r1)
        mu.emu_start(fn | 1, RET, count=100000)
        return mu.reg_read(UC_ARM_REG_R0)

    def hidpp(self, req):
        """req: 20-byte long report -> 20-byte reply."""
        dev, idx, fsw = req[1], req[2], req[3]
        func, p = fsw >> 4, list(req[4:20])
        out = [0] * 16
        def err(code):
            return bytes([0x11, dev, 0xFF, idx, fsw, code] + [0] * 14)
        if idx >= len(self.features):
            return err(5)
        fid = self.features[idx][0]
        if fid == 0x0000:
            if func == 0:
                want = p[0] << 8 | p[1]
                hit = next((i for i, f in enumerate(self.features) if f[0] == want), 0)
                if hit:
                    out[:3] = [hit, self.features[hit][1], self.features[hit][2]]
            elif func == 1:
                out[:3] = [4, 2, p[2]]
        elif fid == 0x0001:
            if func == 0:
                out[0] = len(self.features) - 1
            elif func == 1:
                if p[0] >= len(self.features):
                    return err(2)
                f = self.features[p[0]]
                out[:4] = [f[0] >> 8, f[0] & 0xFF, f[1], f[2]]
        elif fid == 0x0005:
            if func == 0:
                out[0] = len(self.name)
            elif func == 1:
                chunk = self.name[p[0]:p[0] + 16]
                out[:len(chunk)] = chunk
        elif fid == 0x0003:
            self.mu.mem_write(0x20003000, bytes(p) + bytes(16))
            self.mu.mem_write(0x20003100, bytes(32))
            h = self.h_devinfo if func == 0 else self.h_fwinfo if func == 1 else None
            if h is None:
                return err(7)
            rc = self._call(h & ~1, 0x20003000, 0x20003100)
            if rc:
                return err(rc)
            out = list(self._rd(0x20003100, 16))
        else:
            return err(7)
        return bytes([0x11, dev, idx, fsw] + out)


def make_hid(dev):
    rel = 0x2703 if b'U127.03' in dev.img else 0x2701
    info = {'vendor_id': 0x046D, 'product_id': 0xC08B, 'release_number': rel,
            'product_string': 'G502 HERO Gaming Mouse', 'path': b'fake-g502',
            'usage_page': 0xFF00, 'interface_number': 1}

    class FakeDevice:
        def open_path(self, path):
            self.q = []

        def set_nonblocking(self, flag):
            pass

        def write(self, buf):
            buf = bytes(buf)
            if buf[0] == 0x11:
                self.q.append(dev.hidpp(buf))
            return len(buf)

        def read(self, n, timeout_ms=0):
            return list(self.q.pop(0)) if self.q else []

        def close(self):
            pass

    return types.SimpleNamespace(enumerate=lambda vid=0, pid=0: [info], device=FakeDevice)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    dev = G502(sys.argv[1])
    sys.modules['hid'] = make_hid(dev)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import hidpp_version
    sys.argv = ['hidpp_version.py'] + sys.argv[2:]
    hidpp_version.main()


if __name__ == '__main__':
    main()
