"""Run the *real* button-debounce machine code of F-A / F-B under Unicorn.

debounce_sim.py is a hand transcription of the debounce routines; this harness removes the
transcription from the loop. It loads a raw app image, calls the firmware's own
buttons_init / buttons_state_reset once, then once per simulated 1 ms USB frame:

  * between frames, replays contact edges on GPIOC at 10 us resolution; for F-B a closing
    (falling) edge on PC0/PC1 sets EXTI_PR and runs the firmware's EXTI0/EXTI1_IRQHandler,
    exactly as the NVIC would (the handler masks its own line until the next scan)
  * at the frame boundary, writes GPIOC_IDR and calls buttons_scan_debounce
  * reads the per-button "down" flag the firmware will report 200 us later, and clears the
    "changed" flag as buttons_process_events does

Only GPIOC, EXTI and memory are modelled; nothing else in the image runs.

EXTI_PR semantics: on STM32F1/F4/L1 the pending bit is set only when the line is unmasked
(IMR gates the edge before the pending register). `pr_ungated=True` models the opposite
(edges while masked still latch PR, so the IRQ fires as soon as the scan unmasks the line);
it is kept as a sensitivity check because it changes how many history bits a burst of
bounce produces.

usage:
  debounce_emu.py FA.bin FB.bin            scenario table (same scenarios as debounce_sim.py)
  debounce_emu.py FA.bin FB.bin --fuzz N   compare emulation against debounce_sim.py on N
                                           random waveforms
  debounce_emu.py FA.bin FB.bin --sweep    phase-averaged latency vs hold time, chatter,
                                           press bounce and inter-click gap
"""
import random
import struct
import sys

from unicorn import UC_ARCH_ARM, UC_MODE_MCLASS, UC_MODE_THUMB, Uc
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_SP

BASE = 0x08004000
RET = 0x08000100                       # return sentinel (bootloader area, mapped empty)
EXTI_BASE, GPIOC_IDR = 0x40010400, 0x40020810
IMR, FTSR, PR = 0x00, 0x0C, 0x14
STEP = 0.01                            # edge replay resolution, ms

BUILDS = {
    b'U127.01_B0007': dict(name='F-A', init=0x08008164, reset=0x08008270, scan=0x080082a0,
                           exti=None, state=0x20000d18, stride=2, press_thr=0x20000d2e),
    b'U127.03_B0010': dict(name='F-B', init=0x080081e8, reset=0x08008308, scan=0x0800834c,
                           exti=(0x08006dd0, 0x08006e0c), state=0x20000d1d, stride=6,
                           press_thr=0x20000d64),
}


class Firmware:
    def __init__(self, path, pin=0, press_thr=None, pr_ungated=False):
        img = open(path, 'rb').read()
        ver = img[img.find(b'U127.'):][:13]
        self.b = BUILDS[ver]
        self.name = self.b['name']
        self.pin = pin                 # GPIOC pin the simulated contact is wired to
        self.button = None
        self.pr_ungated = pr_ungated
        mu = self.mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        mu.mem_map(0x08000000, 0x10000)
        mu.mem_write(BASE, img)
        mu.mem_map(0x20000000, 0x4000)
        mu.mem_map(0xE0000000, 0x100000)                    # SCB / NVIC
        for page in (0x40000000, 0x40020000):
            mu.mem_map(page, 0x10000)
        self.periph = bytearray(0x1000)                      # SYSCFG / EXTI / TIM9 page
        mu.mmio_map(0x40010000, 0x1000, self._rd, None, self._wr, None)
        self.idr = 0xFFFF
        mu.mem_write(GPIOC_IDR, struct.pack('<I', self.idr))
        self.call(self.b['init'])
        self.call(self.b['reset'])
        self._w8(0x200008f8, 0)                              # boot-combo countdown (u16)
        self._w8(0x200008f9, 0)
        if press_thr is not None:
            self._w8(self.b['press_thr'], press_thr)
        mask_tbl = 0x0800dad8 if self.name == 'F-A' else 0x0800dcbc
        masks = struct.unpack('<11H', bytes(mu.mem_read(mask_tbl, 22)))
        self.button = masks.index(1 << pin)

    # -- EXTI page as MMIO so PR is write-1-to-clear
    def _reg(self, off):
        return struct.unpack_from('<I', self.periph, off & ~3)[0]

    def _rd(self, uc, off, size, ud):
        return int.from_bytes(self.periph[off:off + size], 'little')

    def _wr(self, uc, off, size, val, ud):
        if off == 0x400 + PR:
            struct.pack_into('<I', self.periph, off, self._reg(off) & ~val)
        else:
            self.periph[off:off + size] = val.to_bytes(size, 'little')

    def _w8(self, addr, v):
        self.mu.mem_write(addr, bytes([v & 0xFF]))

    def call(self, fn):
        mu = self.mu
        mu.reg_write(UC_ARM_REG_SP, 0x20003F00)
        mu.reg_write(UC_ARM_REG_LR, RET | 1)
        mu.emu_start(fn | 1, RET, count=200000)

    def edge(self, line_bit):
        """A falling edge on EXTI line `line_bit` (= GPIOC pin number)."""
        if not self.b['exti'] or line_bit > 1:
            return
        if not (self._reg(0x400 + FTSR) >> line_bit) & 1:
            return
        imr = (self._reg(0x400 + IMR) >> line_bit) & 1
        if imr or self.pr_ungated:
            off = 0x400 + PR
            struct.pack_into('<I', self.periph, off, self._reg(off) | (1 << line_bit))
        self._service_irq(line_bit)

    def _service_irq(self, line_bit):
        if self.b['exti'] and (self._reg(0x400 + IMR) >> line_bit) & 1 \
                and (self._reg(0x400 + PR) >> line_bit) & 1:
            self.call(self.b['exti'][line_bit])

    def scan(self, pressed):
        idr = 0xFFFF & ~(1 << self.pin) if pressed else 0xFFFF
        self.mu.mem_write(GPIOC_IDR, struct.pack('<I', idr))
        self.call(self.b['scan'])
        for line in (0, 1):          # a PR latched while masked fires once the scan unmasks
            self._service_irq(line)
        down = False
        for i in range(11):          # buttons_process_events consumes every "changed" bit
            a = self.b['state'] + i * self.b['stride'] + 1
            f = self.mu.mem_read(a, 1)[0]
            self._w8(a, f & ~2)
            if i == self.button:
                down = bool(f & 1)
        return down


def run(fw, wave, ms):
    """Same contract as debounce_sim.run: returns the reported down-state after each tick."""
    out, prev = [], wave(0.0)
    n = round(1 / STEP)
    for t in range(1, ms + 1):
        for k in range(1, n + 1):
            lvl = wave(t - 1 + k * STEP)
            if lvl and not prev:
                fw.edge(fw.pin)
            prev = lvl
        out.append(fw.scan(wave(float(t))))
    return out


def scenario_table(fa, fb):
    import debounce_sim as sim
    for name, wave, ms in sim.SCENARIOS:
        print(f'{name}   (physical: {", ".join(f"{k} {t}" for t, k in wave.edges)})')
        for label, path, thr in (('F-A', fa, None), ('F-B', fb, None),
                                 ('F-A s.0x20', fa, 5), ('F-B s.0x20', fb, 10)):
            ev = sim.edges(run(Firmware(path, press_thr=thr), wave, ms))
            print(f'    {label:11s} {latencies(wave, ev):44s} reported: {ev}')
        print()


def match(wave, ev):
    """[(kind, latency_ms or None)] for each physical edge of `wave` (None = never reported)."""
    out, pending = [], list(ev)
    for i, (t, kind) in enumerate(wave.edges):
        limit = next((u for u, k in wave.edges[i + 1:] if k == kind), float('inf'))
        hit = next((e for e in pending if e[1] == kind and t <= e[0] < limit), None)
        if hit:
            pending = pending[pending.index(hit) + 1:]
        out.append((kind, hit[0] - t if hit else None))
    return out


def latencies(wave, ev):
    return '  '.join(f'{k} {v:+5.1f}ms' if v is not None else f'{k}  LOST '
                     for k, v in match(wave, ev))


def random_wave(rng, ms):
    """Random contact: holds/gaps of 1-60 ms with random sub-ms bounce at every transition."""
    segs, t, closed = [], rng.uniform(2, 6), False
    while t < ms - 40:
        d = rng.choice([rng.uniform(0.2, 3), rng.uniform(3, 15), rng.uniform(15, 60)])
        if closed:
            segs.append((t, t + d))
        t += d
        closed = not closed
    blips = []
    for a, b in segs:
        for edge in (a, b):
            for _ in range(rng.choice([0, 0, 1, 2, 4])):
                s = edge + rng.uniform(-0.2, 2.5)
                blips.append((s, s + rng.uniform(0.02, 0.4)))

    def w(x):
        c = any(a <= x < b for a, b in segs)
        for a, b in blips:
            if a <= x < b:
                c = not c
        return c
    return w


def fuzz(fa, fb, n):
    import debounce_sim as sim
    rng = random.Random(1)
    bad = 0
    for i in range(n):
        ms = 200
        wave = random_wave(rng, ms)
        # model's edge flag = any closing edge sampled in the previous ms (same 10 us grid)
        for path, model in ((fa, sim.FA(2)), (fb, sim.FB(2))):
            emu = run(Firmware(path), wave, ms)
            ref, prev = [], wave(0.0)
            for t in range(1, ms + 1):
                fell = False
                for k in range(1, 101):
                    lvl = wave(t - 1 + k * STEP)
                    fell |= lvl and not prev
                    prev = lvl
                ref.append(model.tick(wave(float(t)), fell))
            if emu != ref:
                bad += 1
                t = next(j for j in range(ms) if emu[j] != ref[j]) + 1
                print(f'  case {i} {"F-A" if model.__class__ is sim.FA else "F-B"}: '
                      f'first mismatch at tick {t}')
    print(f'{n} random waveforms x 2 builds: {bad} mismatches between emulation and model')
    return bad


PHASES = [i / 10 + 0.05 for i in range(10)]   # edge position within the 1 ms frame


def edge_latency(path, make_wave, idx, ms, **kw):
    """Latency of physical edge `idx` over all PHASES: (min, mean, max), or None if any phase
    loses it. make_wave(phase) -> wave with .edges."""
    import debounce_sim as sim
    out = []
    for ph in PHASES:
        w = make_wave(ph)
        ev = sim.edges(run(Firmware(path, **kw), w, ms))
        t, kind = w.edges[idx]
        later = [u for u, k in w.edges[idx + 1:] if k == kind]
        hit = next((e for e in ev if e[1] == kind and t <= e[0] < (later[0] if later else 1e9)),
                   None)
        if hit is None:
            return None
        out.append(hit[0] - t)
    return min(out), sum(out) / len(out), max(out)


def fmt(r):
    return '   lost        ' if r is None else f'{r[1]:5.1f} [{r[0]:4.1f}-{r[2]:4.1f}]'


def sweep(fa, fb):
    """Phase-averaged latency tables (mean [min-max] over 10 edge phases; scan-to-edge ms)."""
    import debounce_sim as sim
    builds = (('F-A', fa, {}), ('F-B', fb, {}), ('F-B PRung', fb, {'pr_ungated': True}))
    hdr = ''.join(f'{n:>18s}' for n, _, _ in builds)

    print('A. Clean click, release latency vs hold time (press latency is identical in all:'
          ' mean 1.5 [1.0-1.9])')
    print(f'{"hold ms":>10s}{hdr}')
    for hold in (3, 6, 9, 11, 12, 14, 17, 20, 22, 25, 30, 50, 100):
        row = [edge_latency(p, lambda ph: sim.clicks((10 + ph, 10 + ph + hold)), 1, 180, **kw)
               for _, p, kw in builds]
        print(f'{hold:10d}' + ''.join(f'{fmt(r):>18s}' for r in row))

    print('\nB. 100 ms hold, release chatter: n contact re-closures (0.1 ms each)')
    for label, gap in (('1 per ms', 1.0), ('3 per ms', 0.3)):
        print(f'{label:>10s}{hdr}')
        for n in (0, 1, 2, 3, 4, 6, 9):
            def mk(ph, n=n, gap=gap):
                t = 10 + ph + 100
                b = tuple((t + 0.2 + i * gap, t + 0.3 + i * gap) for i in range(n))
                return sim.clicks((10 + ph, t), bounce=b)
            row = [edge_latency(p, mk, 1, 200, **kw) for _, p, kw in builds]
            print(f'{n:10d}' + ''.join(f'{fmt(r):>18s}' for r in row))

    print('\nC. 15 ms hold, press bounce: n extra closures 0.3 ms apart; release latency')
    print(f'{"n":>10s}{hdr}')
    for n in (0, 1, 2, 3, 5):
        def mk(ph, n=n):
            t = 10 + ph
            b = tuple((t + 0.1 + i * 0.3, t + 0.2 + i * 0.3) for i in range(n))
            return sim.clicks((t, t + 15), bounce=b)
        row = [edge_latency(p, mk, 1, 150, **kw) for _, p, kw in builds]
        print(f'{n:10d}' + ''.join(f'{fmt(r):>18s}' for r in row))

    print('\nD. Two 40 ms clicks separated by a gap: latency of the 2nd press')
    print(f'{"gap ms":>10s}{hdr}')
    for gap in (3, 5, 7, 9, 10, 11, 12, 15, 20, 25):
        def mk(ph, gap=gap):
            t = 10 + ph
            return sim.clicks((t, t + 40), (t + 40 + gap, t + 80 + gap))
        row = [edge_latency(p, mk, 2, 200, **kw) for _, p, kw in builds]
        print(f'{gap:10d}' + ''.join(f'{fmt(r):>18s}' for r in row))

    print('\nE. Steady clean tapping, 50% duty, 12 clicks: mean press / release latency, '
          'clicks lost (all phases)')
    print(f'{"CPS":>10s}' + ''.join(f'{n:>24s}' for n, _, _ in builds[:2]))
    for cps in (5, 8, 10, 12, 15, 18, 20, 25):
        period = 1000 / cps
        row = []
        for _, p, kw in builds[:2]:
            down, up, lost = [], [], 0
            for ph in PHASES:
                w = sim.clicks(*[(10 + ph + i * period, 10 + ph + i * period + period / 2)
                                 for i in range(12)])
                ev = sim.edges(run(Firmware(p, **kw), w, int(20 + 13 * period)))
                for kind, v in match(w, ev):
                    if v is None:
                        lost += kind == 'down'
                    else:
                        (down if kind == 'down' else up).append(v)
            row.append(f'{sum(down) / len(down):5.1f} / {sum(up) / len(up):5.1f}  '
                       f'{lost / len(PHASES):4.1f}')
        print(f'{cps:10d}' + ''.join(f'{r:>24s}' for r in row))


def load_trace(path, col=1, active_low=True):
    """Logic-analyzer CSV (e.g. PulseView/sigrok export): time in seconds in column 0, the
    switch line in column `col`. Returns [(t_ms, closed)] at every level change, t from 0."""
    rows = []
    for line in open(path):
        f = [x.strip() for x in line.replace(';', ',').split(',')]
        try:
            t, v = float(f[0]), int(float(f[col]))
        except (ValueError, IndexError):
            continue                                      # header / comment
        closed = (v == 0) if active_low else (v == 1)
        if not rows or rows[-1][1] != closed:
            rows.append((t * 1000.0, closed))
    t0 = rows[0][0]
    return [(t - t0, c) for t, c in rows]


def run_edges(fw, edges, ms, offset):
    """Replay exact edges (no sampling grid): each closing edge goes to EXTI as it happens,
    each 1 ms frame boundary scans the level. `offset` shifts the trace vs. frame phase."""
    out, k, level = [], 0, edges[0][1]
    ev = [(t + offset, c) for t, c in edges]
    for tick in range(1, ms + 1):
        while k < len(ev) and ev[k][0] <= tick:
            if ev[k][1] and not level:
                fw.edge(fw.pin)
            level = ev[k][1]
            k += 1
        out.append(fw.scan(level))
    return out


def trace_report(fa, fb, path, col):
    """Per-click latency of F-A vs F-B on a recorded switch waveform, over 10 frame phases."""
    import debounce_sim as sim
    edges = load_trace(path, col)
    end = int(edges[-1][0]) + 80
    # "true" transitions: edges closer than `stable` ms form one bounce burst; a burst that
    # ends in a new level is a physical press/release starting at the burst's first edge
    phys, stable, level, start = [], 3.0, edges[0][1], None
    for i, (t, c) in enumerate(edges[1:], 1):
        if start is None or t - edges[i - 1][0] >= stable:
            start = t
        nxt = edges[i + 1][0] if i + 1 < len(edges) else float('inf')
        if nxt - t >= stable and c != level:
            phys.append((start, c))
            level = c
    print(f'{path}: {len(edges)} level changes, {sum(1 for _, c in phys if c)} clicks '
          f'(edges closer than {stable} ms grouped as bounce)')
    for label, p in (('F-A', fa), ('F-B', fb)):
        stats = {'down': [], 'up': []}
        lost = 0
        for ph in PHASES:
            states = run_edges(Firmware(p), edges, end, 10 + ph)
            ev = sim.edges(states)
            w = type('W', (), {})()
            w.edges = [(t + 10 + ph, 'down' if c else 'up') for t, c in phys]
            for kind, v in match(w, ev):
                if v is None:
                    lost += kind == 'down'
                else:
                    stats[kind].append(v)
        for kind in ('down', 'up'):
            v = stats[kind]
            if v:
                print(f'  {label} {kind:4s}: mean {sum(v) / len(v):5.1f} ms  '
                      f'min {min(v):4.1f}  max {max(v):5.1f}  (n={len(v)})')
        print(f'  {label} clicks lost/merged: {lost / len(PHASES):.1f}')


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    fa, fb = sys.argv[1], sys.argv[2]
    if '--fuzz' in sys.argv:
        sys.exit(1 if fuzz(fa, fb, int(sys.argv[sys.argv.index('--fuzz') + 1])) else 0)
    if '--sweep' in sys.argv:
        return sweep(fa, fb)
    if '--trace' in sys.argv:
        i = sys.argv.index('--trace')
        col = int(sys.argv[i + 2]) if len(sys.argv) > i + 2 else 1
        return trace_report(fa, fb, sys.argv[i + 1], col)
    scenario_table(fa, fb)


if __name__ == '__main__':
    main()
