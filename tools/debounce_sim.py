"""Cycle-level model of the G502 HERO button debounce in firmware 127.01.07 (F-A) and
127.03.10 (F-B), transcribed from the disassembly:

  F-A  FUN_080082a0   (scan, once per 1 ms USB frame)
  F-B  FUN_0800834c   (scan) + EXTI0/EXTI1_IRQHandler (falling-edge latch on PC0/PC1)

Buttons are active-low GPIOC inputs sampled once per frame. One simulated tick = one USB
start-of-frame = 1 ms. A button event is reported in the HID report built 200 us later in
the same frame, so "latency" below = (tick the state flips) - (time of the physical edge).

usage: debounce_sim.py           (prints a scenario table)
"""


def s8(v):
    v &= 0xFF
    return v - 0x100 if v & 0x80 else v


class FA:
    """127.01.07: press after N stable ticks, release after 2, then a 20 tick lockout."""

    def __init__(self, press_thr=2):
        self.press_thr = press_thr
        self.cnt = 0
        self.flags = 0

    def tick(self, pressed, edge_flag=False):
        if self.cnt < 0:
            self.cnt += 1                     # lockout: input ignored
        elif pressed:
            if self.flags & 1:
                self.cnt = 0
            else:
                self.cnt = s8(self.cnt + 1)
                if self.cnt >= self.press_thr:
                    self.flags |= 3
                    self.cnt = -20
        else:
            if self.flags & 1:
                self.cnt = s8(self.cnt + 1)
                if self.cnt > 1:
                    self.flags = (self.flags & ~1) | 2
                    self.cnt = -20
            else:
                self.cnt = 0
        return bool(self.flags & 1)


class FB:
    """127.03.10: adaptive release threshold from a 32 ms falling-edge history."""

    def __init__(self, press_thr=2):
        self.press_thr = press_thr
        self.hist = 0                         # DAT_20000d60 / DAT_20000d68
        self.st = [0, 0, 0, 0, 0, 0]          # cnt, flags, p2, p3, p4, p5
        self.release_thr = 4

    def tick(self, pressed, edge_flag=False):
        self.hist = ((self.hist << 1) | int(edge_flag)) & 0xFFFFFFFF
        self.release_thr = min((bin(self.hist).count('1') + 2) * 2, 20)
        s = self.st
        cnt = s8(s[0])
        if pressed:
            if cnt < 0:
                s[2] = (s[2] + 1) & 0xFF
                new = s8(cnt + 1)
                s[0] = new
                if s[5]:
                    if s[3] <= 9:
                        if ((cnt + 0x28) & 0xFF) <= 0x13:
                            s[0] = s8(cnt + 0x15)
                        elif new >= -19:
                            s[0] = 0
                    s[5] = 0
                s[3] = 0
            elif s[1] & 1:
                s[0] = 0
                s[3] = 0
            else:
                s[0] = s8(cnt + 1)
                if s[0] >= self.press_thr:
                    s[1] |= 3
                    s[0] = -20
                    s[2] = 0
                    s[4] = 1
        else:
            if cnt < 0:
                s[3] = (s[3] + 1) & 0xFF
                new = s8(cnt + 1)
                s[0] = new
                if s[4]:
                    if s8(s[2]) <= 9 and new >= -19:
                        s[0] = s8(cnt - 0x13)
                    s[4] = 0
                s[2] = 0
            elif s[3] <= 4:
                s[0] = s8(s[3] - 5)
            elif s[1] & 1:
                s[0] = s8(cnt + 1)
                if s[0] >= self.release_thr:
                    s[1] = (s[1] & ~1) | 2
                    s[0] = -20
                    s[3] = 0
                    s[5] = 1
            else:
                s[0] = 0
        return bool(s[1] & 1)


def run(model, wave, ms):
    """wave(t_ms) -> True when the contact is closed. Sampled at 0.05 ms for edges."""
    out, prev_level, sub = [], wave(0.0), 20
    for t in range(1, ms + 1):
        fell = False
        for k in range(1, sub + 1):
            lvl = wave(t - 1 + k / sub)
            fell |= lvl and not prev_level   # closing contact = falling edge on active-low pin
            prev_level = lvl
        out.append(model.tick(wave(float(t)), fell))
    return out


def edges(states):
    ev, prev = [], False
    for t, s in enumerate(states, 1):
        if s != prev:
            ev.append((t, 'down' if s else 'up'))
            prev = s
    return ev


def clicks(*holds, bounce=()):
    """Contact closed during each (down, up) hold; each (start, end) bounce window inverts it."""
    def w(t):
        closed = any(a <= t < b for a, b in holds)
        for a, b in bounce:
            if a <= t < b:
                closed = not closed
        return closed
    w.edges = [e for a, b in holds for e in ((a, 'down'), (b, 'up'))]
    return w


def chatter(t, n):
    """n short contact re-closures, one per ms, starting 0.5 ms after t."""
    return tuple((t + i + 0.5, t + i + 0.6) for i in range(n))


SCENARIOS = [
    ('clean 100 ms hold', clicks((10.3, 110.3)), 140),
    ('clean 20 ms tap', clicks((10.3, 30.3)), 80),
    ('100 ms hold, 2 ms release chatter', clicks((10.3, 110.3), bounce=chatter(110.3, 2)), 160),
    ('100 ms hold, 5 ms release chatter', clicks((10.3, 110.3), bounce=chatter(110.3, 5)), 160),
    ('25 ms hold, 1 ms press bounce', clicks((10.3, 35.3), bounce=((10.5, 10.6), (11.0, 11.1))), 90),
    ('2 clicks: 40 ms holds, 15 ms gap', clicks((10.3, 50.3), (65.3, 105.3)), 150),
    ('2 clicks: 40 ms holds, 8 ms gap', clicks((10.3, 50.3), (58.3, 98.3)), 150),
]

MODELS = (
    ('F-A', lambda: FA(2)),
    ('F-B', lambda: FB(2)),
    # press threshold while sensor status bit 0x20 is set (and 100 ms after); meaning unknown
    ('F-A s.0x20', lambda: FA(5)),
    ('F-B s.0x20', lambda: FB(10)),
)


def main():
    for name, wave, ms in SCENARIOS:
        print(f'{name}   (physical: {", ".join(f"{k} {t}" for t, k in wave.edges)})')
        for label, make in MODELS:
            ev = edges(run(make(), wave, ms))
            lat, pending = [], list(ev)
            for i, (t, kind) in enumerate(wave.edges):
                limit = next((u for u, k in wave.edges[i + 1:] if k == kind), float('inf'))
                hit = next((e for e in pending if e[1] == kind and t <= e[0] < limit), None)
                if hit:
                    pending = pending[pending.index(hit) + 1:]
                lat.append(f'{kind} {hit[0] - t:+5.1f}ms' if hit else f'{kind}  LOST ')
            print(f'    {label:11s} {"  ".join(lat):44s} reported: {ev}')
        print()


if __name__ == '__main__':
    main()
