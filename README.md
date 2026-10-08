# G502 HERO firmware decomp

Reverse engineering of the Logitech G502 HERO (USB `046d:c08b`) mouse firmware, aimed at one
question: **why does firmware 127.03.10 add so much click-release latency compared with
127.01.07, and what would it take to get the old behaviour on newer units?**

| Name | Version (in image) | Where it comes from |
|---|---|---|
| **F-A** | 127.01.07 (`U127.01_B0007`) | Standalone *G502 HERO Firmware Update Tool* (2019), resource `FIRMWARE` |
| **F-B** | 127.03.10 (`U127.03_B0010`) | G HUB package `g502_hero_dfu`, still the only G502 HERO firmware G HUB serves (checked against G HUB 2026.6.981214) |
| F-C | ? | Whatever newer G502 HERO units ship with — not identified yet (see [open questions](#open-questions)) |

## TL;DR

* F-A and F-B are the same program for the same hardware: **315 of 323 functions are
  instruction-for-instruction identical**. Every real change is in button debouncing.
* F-A reports a release after **2 consecutive released samples** (~1–2 ms).
* F-B reports a release only after a fixed 5 ms "is it really released?" wait **plus** an
  adaptive count of 4–20 samples, sized from how many contact-closing edges PC0/PC1 saw in the
  last 32 ms. That is **~10 ms for a perfectly clean release and up to ~20 ms with chatter**.
  The adaptive threshold is shared by all 11 buttons.
* Side effect: in F-B two clicks separated by less than ~10 ms merge into one long click.

## Getting the firmware

Firmware binaries are not committed. To recreate `firmware/`:

```sh
pip install pefile capstone
python3 tools/ghub_fetch.py get dl g502_hero_dfu          # F-B straight from Logitech's G HUB CDN
python3 tools/fw_extract.py dl/g502_hero_dfu/g502_hero_v127_03_10.dfu firmware/FB_127_03_10.bin
python3 tools/fw_extract.py G502HERO_Update_127.1.7.exe firmware/FA_127_01_07.bin
GHIDRA=/path/to/ghidra_11.4.2_PUBLIC ghidra/run.sh firmware/FA_127_01_07.bin firmware/FB_127_03_10.bin
```

`tools/ghub_fetch.py list` lists all 780 G HUB packages. Its manifest comes from
`https://updates.ghub.logitechg.com/pipeline/v2/update/ghub13/win/public/details.json` (path
format recovered from `logi_installer_shared.dll` inside the G HUB installer).

Expected SHA-256 of the `.dfu` containers:

```
b8f62a820cb3070c08870211b80ba329b8a8424a4f0e151d360214dd046855c6  F-A 127.01.07
85fcfc43ba988e361af5ccfb31c0b1f8238080ce699adec9d12f9ce4e381d268  F-B 127.03.10
```

## Platform (from the code)

* **MCU: STM32L1 medium density, Cortex-M3.** Peripheral addresses (RCC `0x40023800`, FLASH
  `0x40023C00`, GPIO `0x40020000`, USB `0x40005C00`), the 45-IRQ vector table and the
  `BootRAM` word at vector offset `0x108` all match `startup_stm32l1xx_md`. PLL = HSE×12/3
  (8 MHz crystal → 96 MHz VCO for USB, 32 MHz core).
* **Flash layout:** bootloader at `0x08000000–0x08003FFF` (not part of any update file), app at
  `0x08004000`, `0xAF00` bytes.
* **Update container** (`.dfu`): 32-byte header (`U127_D1`, load address, length), image, then a
  256-byte high-entropy block that looks like an RSA-2048 signature. Both versions share the
  same layout.
* **Buttons:** 11 active-low inputs on GPIOC, mask `0x4F9F`, scanned in the order
  PC0, PC1, PC2, PC3, PC4, PC10, PC9, PC8, PC11, PC7, PC14. PC0/PC1 are the primary clicks
  (only they get the new EXTI edge latch in F-B; left/right order not confirmed).
* **Sensor:** SPI1, chip select PA4. `sensor_poll_status` reads a status byte + 4 data bytes each
  frame. Bit 7 gates motion processing.
* **Timing:** the main loop waits for USB start-of-frame (1 ms, 3 ms timeout, TIM9 at 2 MHz),
  scans the buttons at frame start, and `buttons_process_events` consumes them 200 µs later.
  **One debounce tick = 1 ms.**

## What changed between F-A and F-B

`tools/match_functions.py` output (F-A → F-B):

| F-A | F-B | What |
|---|---|---|
| `buttons_scan_debounce` `080082a0` | `popcount32` `08008338` + `buttons_scan_debounce` `0800834c` | New debounce algorithm (below) |
| `EXTI0/1_IRQHandler` | `EXTI0/1_IRQHandler` | Now latch "edge seen" flags for PC0/PC1 and mask the line until the next scan |
| `buttons_init` `08008164` | `080081e8` | Adds falling-edge EXTI interrupts on PC0/PC1 |
| `FUN_080076b0` | `FUN_08007720` | Sleep/wake path re-enables those interrupts |
| `buttons_process_events` `08008660` | `0800883c` | Per-button state grew from 2 to 6 bytes (stride change only) |
| — | `EXTI_GetITStatus` `080046d8` | StdPeriph helper newly linked in |

(`0800ea50`/`0800ea78` in F-A are flash-status helpers that also exist byte-identical in F-B at
`0800ec38`; Ghidra just didn't auto-detect them there.)

### F-A debounce (`decomp/FA_127_01_07.c`, `buttons_scan_debounce`)

Per button: `cnt` (signed) and `flags` (bit0 = down, bit1 = changed).

* `cnt < 0` → lockout, `cnt++`, input ignored.
* pressed & up → `cnt++`; at `press_thr` (2, or 5 when sensor status bit `0x20` was set within
  the last 100 ms) report **down**, `cnt = -20`.
* released & down → `cnt++`; at 2 report **up**, `cnt = -20`.

### F-B debounce (`decomp/FB_127_03_10.c`, `buttons_scan_debounce`)

Every tick:

```c
hist0 = (hist0 << 1) | pc0_falling_edge_seen;   // 32 ms history per primary button
hist1 = (hist1 << 1) | pc1_falling_edge_seen;
release_thr = min(2 * (max(popcount(hist0), popcount(hist1)) + 2), 20);   // 4..20, all buttons
```

Per button there are now 6 bytes. On a release the button must first stay released for 5 ticks
(`p3` counter: any bounce back to pressed restarts it), then for `release_thr` more ticks. Press
threshold is 2, or **10** when sensor status bit `0x20` was set (was 5). There is also extra
logic that shortens the 20-tick lockout when a button is re-pressed soon after a release.

### Simulated latency

`tools/debounce_sim.py` is an instruction-level transcription of both routines (1 ms ticks,
edges sampled at 50 µs). Physical edge → reported state change:

| Scenario | F-A down | F-A up | F-B down | F-B up |
|---|---|---|---|---|
| clean 100 ms hold | 1.7 | 1.7 | 1.7 | **9.7** |
| clean 20 ms tap | 1.7 | 3.7 | 1.7 | **11.7** |
| 100 ms hold, 2 ms release chatter | 1.7 | 1.7 | 1.7 | **13.7** |
| 100 ms hold, 5 ms release chatter | 1.7 | 1.7 | 1.7 | **19.7** |
| 2nd click after a 15 ms gap | 8.7 | 1.7 | 2.7 | 9.7 |
| 2nd click after an 8 ms gap | 15.7 | 1.7 | **merged into the 1st click** | |

(ms, edges placed 0.3 ms after a frame boundary; add 0–1 ms for real-world phase.) With sensor
status bit `0x20` set, press latency becomes ~5 ms (F-A) / ~10 ms (F-B). That bit's meaning is
unknown; lift detection is a guess.

## Open questions

1. **What do new G502 HERO units run?** G HUB only serves F-B for `046d:c08b`. Either new units
   run F-B too and refuse F-A for another reason (bootloader rollback/signature check, changed
   hardware), or they enumerate differently and get firmware from one of the 148 encrypted G HUB
   packages. Firmware version + VID:PID from a new unit would settle this.
2. **Encrypted G HUB packages** (magic `0x20210506`, AES-128 key ids served from
   `/pipeline/v2/access/<group>/content.json`) — the scheme isn't plain AES-CBC/CTR/GCM with
   those keys; needs more work in `logi_installer_shared.dll`.
3. **Does the bootloader enforce the signature?** Decides whether a patched F-B (F-A release
   logic) could be flashed at all. Needs a unit or a bootloader dump.
4. Meaning of sensor status bit `0x20`.

## Layout

```
tools/ghub_fetch.py       list/download/unpack G HUB depots
tools/fw_extract.py       .dfu or old updater .exe -> raw image (.bin)
ghidra/                   headless setup (STM32L1 map, vector table), export, symbol names
decomp/                   generated: decompiled C + function tables per version
tools/match_functions.py  function-level diff of two exports
tools/diff_func.py        diff one function's C between versions
tools/show_func.py        print a function from an export
tools/thumbdis.py         small capstone disassembler with literal-pool annotations
tools/debounce_sim.py     F-A / F-B debounce model + latency scenarios
```
