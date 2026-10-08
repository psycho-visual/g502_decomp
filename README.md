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

* F-A and F-B are the same program for the same hardware. A whole-image, relocation-aware diff
  (`tools/image_diff.py`, which does not depend on Ghidra's function list) accounts for **every**
  difference, and there are exactly three kinds:
  1. the new button debounce / EXTI handling (8 functions, 2 new helpers);
  2. **max DPI 16000 → 25600**: in the sensor programming and in the HID++ 0x2201 DPI list
     and set-DPI bound reported to G HUB;
  3. **version metadata only**: HID++ `getFwInfo`, the version string, and the USB
     `bcdDevice` (`0x2701` → `0x2703`). The "init constant 7 → 16" is the BCD **build number**
     reported over HID++ (B000**7** → B00**10**), not a setting.
* F-A reports a release after **2 consecutive released samples**: 1.5 ms on average
  (1.0–2.0 ms over frame phase).
* F-B reports a release only after a 5-sample "stays released" wait **plus** an adaptive 4–20
  samples, sized from how many contact-closing edges PC0/PC1 saw in the last 32 ms:
  **9.5 ms on average for a clean release (+8 ms vs F-A)**, ~2 ms more per millisecond of
  release chatter. The adaptive threshold is shared by all 11 buttons.
* These numbers come from running the **real machine code** of both builds in an emulator
  (`tools/debounce_emu.py`), and the hand model `tools/debounce_sim.py` now matches that code
  tick for tick on 1,500 random bouncy waveforms.
* F-B side effects: releases shorter than ~10 ms are not reported at all (two clicks merge),
  and a **tap held ≤ 11 ms is reported as released ~45 ms after it began** (F-A: ~23 ms),
  because F-B extends the lockout after very short presses.
* New units: the old updater refuses any mouse already on ≥ 127.01.07 unless run with
  `/FORCE`, and only talks to PIDs `C08B` / `AAE6` and DFU-control features `0x00C0–0x00C2`.
  `tools/hidpp_version.py` now reads and **interprets** everything needed to tell which gate a
  new unit fails (see [What the mouse reports](#what-the-mouse-reports-and-what-the-old-updater-checks)).

## Getting the firmware

Firmware binaries are not committed. To recreate `firmware/`:

```sh
pip install pefile capstone unicorn
python3 tools/ghub_fetch.py get dl g502_hero_dfu          # F-B straight from Logitech's G HUB CDN
python3 tools/fw_extract.py dl/g502_hero_dfu/g502_hero_v127_03_10.dfu firmware/FB_127_03_10.bin
curl -LO https://download01.logi.com/web/ftp/pub/techsupport/gaming/G502HERO_Update_127.1.7.exe
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
* **Timing:** the main loop spins until `usb_sof_callback` sets the SOF flag `0x20000e4f`
  (or 3 ms pass; TIM9 at 2 MHz). Ghidra dropped that volatile read, so the C shows a bare
  3 ms wait, but the disassembly at F-B `08006a28` has it. Each frame runs `sensor_poll_status`,
  then `buttons_scan_debounce`, then waits until SOF+200 µs for `buttons_process_events`. Both
  HID interrupt endpoints have `bInterval = 1` (1 ms polling). **One debounce tick = 1 ms.**
  Everything after the state flip (+0.2 ms to queue the report, then the next host poll) is the
  same in both builds, so it shifts absolute latency but not the F-A/F-B difference.

## What changed between F-A and F-B

`tools/match_functions.py` output (F-A → F-B):

| F-A | F-B | What |
|---|---|---|
| `buttons_scan_debounce` `080082a0` | `popcount32` `08008338` + `buttons_scan_debounce` `0800834c` | New debounce algorithm (below) |
| `EXTI0/1_IRQHandler` | `EXTI0/1_IRQHandler` | Now latch "edge seen" flags for PC0/PC1 and mask the line until the next scan |
| `buttons_init` `08008164` | `080081e8` | Adds falling-edge EXTI interrupts on PC0/PC1 |
| `FUN_080076b0` | `FUN_08007720` | Sleep/wake path re-enables those interrupts |
| `buttons_process_events` `08008660` | `0800883c` | Per-button state grew from 2 to 6 bytes (stride change only) |
| `buttons_state_reset` `08008270` | `08008308` | Same 2→6 byte stride; resets release threshold |
| — | `EXTI_GetITStatus` `080046d8` | StdPeriph helper newly linked in |
| — | `popcount32` `08008338` | Helper for the adaptive release threshold |

Also part of the debounce change: `sensor_poll_status` `080079d4` → `08007a5c` raises the
press threshold used while sensor status bit `0x20` is set from 5 to **10**.

Everything else that differs (`tools/image_diff.py` output, F-A → F-B):

| Where (F-B) | F-A → F-B | What |
|---|---|---|
| `FUN_08007d44` | `0x3e80` → `0x6400` | Sensor CPI programming (regs 3/0x0c/0x0d, 50-CPI steps below 12800, 100 above): **max DPI 16000 → 25600** |
| `08007e6c` (HID++ 0x2201 `getSensorDpiList`, not a Ghidra function) | `0064 E032 3E80` → `0064 E032 6400` | DPI range reported to G HUB: 100…16000 → 100…25600, step 50 |
| `08007eb4` (HID++ 0x2201 `setSensorDpi`) | `dpi−100 ≤ 0x3e1c` → `≤ 0x639c` | accepted DPI range, same change |
| `08005aec` (HID++ 0x0003 `getFwInfo`, not a Ghidra function) | `27.01` → `27.03` | reported app version |
| `FUN_0800b124` (was "init constant 7 → 16") | `{0x00, 0x07}` → `{0x00, 0x10}` | RAM `0x20000df4/5` = the BCD **build** that `getFwInfo` reports: B0007 → B0010 |
| USB device descriptor `0800cc7b` | `bcdDevice 0x2701` → `0x2703` | shows as `REV_2703` in Windows hardware IDs |
| `0800e236` | `U127.01_B0007` → `U127.03_B0010` | version string |

The rest of the diff is layout: alignment NOPs, literal pools, one prel31 unwind word, and
trailing zero padding. The trailing flash-status helpers (`0800ea50`/`0800ea78` in F-A) are
byte-identical in F-B at `0800ec38`. Ghidra's function list covers only ~58% of each image
(HID++ feature handlers are reached through pointer tables), so `verify_changes.py` alone
could not see the getFwInfo, DPI-list or descriptor changes. Use `image_diff.py` for
completeness.

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

Per button there are now 6 bytes (`cnt, flags, p2, p3, p4, p5`). On a release the button must
first stay released for 5 ticks (`p3` counter: any bounce back to pressed restarts it), then for
`release_thr` more ticks. Press threshold is 2, or **10** when sensor status bit `0x20` was set
(was 5). Lockout tweaks around the 20-tick lockout:

* re-pressed within 10 released ticks of a reported release → lockout cancelled (`cnt = 0`),
  so quick re-presses register faster than in F-A;
* released within 10 pressed ticks of a reported press → lockout **extended by 19 ticks**
  (`cnt -= 19`), so a very short tap's release is held back for ~40 ms.

Both builds skip the per-button loop entirely while every button reads released and nothing
was active last tick (`DAT_200008f6 == 0`). The original model lacked this early-out, but it
never affected the scenario numbers.

### Latency, from the real code

`tools/debounce_emu.py` loads each image into Unicorn and calls the firmware's own
`buttons_init`, `buttons_state_reset` and then `buttons_scan_debounce` once per 1 ms frame.
Contact edges are replayed at 10 µs resolution; for F-B a closing edge raises EXTI_PR and runs
the real `EXTI0/1_IRQHandler`. After each frame it clears the "changed" bit, as
`buttons_process_events` does. Checks:

* `debounce_emu.py FA.bin FB.bin` reproduces the old model's scenario table exactly;
* `--fuzz 1500` runs 1,500 random bouncy waveforms through both and through
  `debounce_sim.py`: **0 mismatches** (after adding the idle early-out and the consumed
  "changed" bit to the model).

Numbers below are `--sweep` output: physical edge → frame in which the reported state flips,
**mean [min–max] over 10 edge phases within the 1 ms frame**. Add ~0.2 ms + host polling (same
for both builds). Press latency for a clean press is 1.5 [1.0–1.9] ms in both builds.

**Clean release vs hold time**

| hold (ms) | 3 | 9 | 11 | 12 | 14 | 17 | 20 | 22 | ≥ 25 |
|---|---|---|---|---|---|---|---|---|---|
| F-A up | 20.5 | 14.5 | 12.5 | 11.5 | 9.5 | 6.5 | 3.5 | 1.5 | **1.5** |
| F-B up | 42.5 | 36.5 | 34.5 | 15.5 | 13.5 | 10.5 | 11.5 | 10.5 | **9.5** |

Under ~22 ms both builds are still in the post-press lockout. For F-B, holds of 12–22 ms also
keep the press's own closing edge in the 32 ms history (threshold 6 instead of 4). Holds of
11 ms or less hit the lockout extension.

**Release chatter** (100 ms hold, n contact re-closures after the release, one per ms):
F-B up = 9.5 / 11.6 / 13.7 / 15.8 / 17.9 ms for n = 0…4, i.e. **+2.1 ms per chattering
millisecond**. F-A stays at 1.5–1.9 ms. Several re-closures inside one millisecond count once.
**Press bounce** only matters when the release follows within ~22 ms: 15 ms hold, F-B
12.5 → 14.4 ms with 0 → 3 bounces (F-A 8.5 → 8.8).

**Two 40 ms clicks, latency of the second press vs gap**

| gap (ms) | 3–9 | 10–15 | 20 | 25 | ≥ 30 |
|---|---|---|---|---|---|
| F-A | 20.5 → 14.5 | 13.5 → 8.5 | 3.5 | 1.5 | 1.5 |
| F-B | **lost (merged)** | 2.5 | 11.5 | 6.5 | 1.5 |

**Steady clean tapping, 50% duty** (press / release mean, ms):

| CPS | ≤ 15 | 18 | 20 | 25 |
|---|---|---|---|---|
| F-A | 1.5 / 1.5 | 1.5 / 1.5 | 1.5 / 1.5 | 9.5 / 11.5, 2 of 12 clicks lost |
| F-B | 1.5 / 9.5 | 3.5 / 9.5 | 6.1 / 9.5 | 2.4 / 11.5, none lost |

So for ordinary clicking F-B adds a flat ~8 ms to every release. That grows with chatter and
is much worse for very short taps, while very fast spam (≥ 25 CPS, 20 ms holds) is handled
better by F-B.

EXTI_PR sensitivity: on STM32L1 the pending bit is gated by IMR, so edges while the line is
masked are dropped. The emulator models that by default. The opposite assumption
(`pr_ungated=True`) changes only the cases with several bounce edges inside one millisecond,
by up to +2 ms.

With sensor status bit `0x20` set, press latency becomes ~5 ms (F-A) / ~10 ms (F-B). That
bit's meaning is unknown; lift detection is a guess.

**Measuring your own switch.** What is left uncertain is your switches' real bounce, which
drives F-B's adaptive part. Record the switch contact with any logic analyzer (one probe on the
switch's normally-open terminal, ground to the mouse's ground; nothing is written to the mouse).
Export CSV from PulseView/sigrok, then:

```sh
python3 tools/debounce_emu.py FA.bin FB.bin --trace clicks.csv [column]
```

This replays the recorded edges exactly through both builds' real code (averaged over frame
phase) and prints per-build press/release latency and merged clicks for **your** switch.

## What the mouse reports, and what the old updater checks

### HID++ / USB fingerprint of F-A and F-B (read out of the images)

| Source | F-A | F-B | Notes |
|---|---|---|---|
| USB PID / `bcdDevice` | `C08B` / `2701` | `C08B` / `2703` | Windows: `USB\VID_046D&PID_C08B&REV_2703` in Device Manager |
| 0x0003 entity 0 (app) | `U127.01_B0007`, pid C08B, active | `U127.03_B0010`, pid C08B, active | name `"U1 "`, number/rev BCD, build from RAM |
| 0x0003 entity 1 (bootloader) | `BOT81.00_B????`, pid AAE6 | same | **"BOT" and 81.00 are constants in the app**; only the build is read from bootloader flash (ASCII digits at `0x08003FF6/8/A/C`) |
| 0x0003 getDeviceInfo | 2 entities, transport `0008`, modelId `c08b00000000` | same | unitId = first 32 bits of the STM32 unique ID (per-unit serial); **extendedModelId = factory EEPROM byte `0x08080170`** (CRC-16 checked) |
| feature table | 0x0003 v2, 0x0005 v3, 0x1300 v8, 0x2201 v4, 0x8060 v3, 0x8100 v13, 0x8110 v5, **0x00C2 v2**, hidden: 0x18A1, 0x1E00, 0x1E22, 0x1EB0, 0x1801, 0x1802, 0x1806, 0x18B1 | identical | |

### The 127.1.7 updater's gates (`G502HERO_Update_127.1.7.exe`)

1. **PID filter**: it reacts only to `C08B` (app running, go to 2) and `AAE6` (bootloader,
   flash immediately with no version check). Anything else is ignored ("Please connect your
   device to continue").
2. **Version gate**: it reads 0x0003, parses minor/build, and if `(minor << 16 | build) >=
   0x10007` it stops with *"Your device has firmware v127.1.7 or higher. No update is
   needed."* That is true for **every** F-B mouse, old or new. The `/FORCE` command-line switch
   skips this gate. That is what the known downgrade method uses.
3. **Entering DFU** uses DFU-control feature `0x00C0`, `0x00C1` or `0x00C2`, and the transfer
   uses `0x00D0` in the bootloader. A unit that only offers `0x00C3` (secure DFU) can't be put
   into its bootloader by this tool.
4. **The bootloader itself** decides whether to accept the image (signature, and possibly
   anti-rollback or a hardware check). The tool only sees DFU status errors here and retries
   ("The firmware updated failed…").
5. `/LOG` writes `Documents\G502HeroFirmwareUpdate.log` with the PID seen, the parsed
   minor/build and DFU errors. A log from a failed attempt on a new unit pinpoints the stage.

### Reading a new unit

`pip install hidapi`, then `python tools/hidpp_version.py`. It is read-only (Root, FeatureSet,
DeviceInfo and DeviceName *get* calls only) and prints an **interpretation** section that applies
the tables above. `unitId` is hidden unless you pass `--show-unit-id`, so the output is safe to
post. Best practice: run it on an older unit and a newer one and compare. What each outcome means:

| New unit shows | Meaning |
|---|---|
| PID ≠ `C08B` | different product ID: the old updater ignores it outright (gate 1) |
| `rel 2703`, `U127.03_B0010`, same features | same F-B app as G HUB serves; any refusal is in the bootloader (gate 4) or hardware |
| app version other than 27.01/27.03 | new factory firmware ("F-C") that G HUB doesn't distribute |
| bootloader build differs from an older unit | different bootloader; prime suspect for gate 4 |
| bootloader PID ≠ `AAE6` | old updater loses the mouse after reboot into DFU |
| `0x00C3` instead of `0x00C2` | old updater can't enter DFU (gate 3) |
| `extendedModelId` differs from an older unit | factory-marked hardware variant |

`tools/hidpp_fake.py FB.bin` runs `hidpp_version.py` against a fake device whose 0x0003 replies
come from the image's real handlers (placeholders for the unique ID, the EEPROM byte and the
bootloader build), as a self-test of the parsing and interpretation.

## Open questions

1. **What do new G502 HERO units report?** Needs `hidpp_version.py` output (and ideally the same
   from an older unit) to place them in the table above.
2. **Encrypted G HUB packages** (magic `0x20210506`, AES-128 key ids served from
   `/pipeline/v2/access/<group>/content.json`). The scheme isn't plain AES-CBC/CTR/GCM with
   those keys; it needs more work in `logi_installer_shared.dll`.
3. **What does the bootloader check?** Signature, rollback or hardware checks decide whether
   any F-A could be accepted on newer bootloaders. Needs a bootloader dump or a `/LOG` trace
   from a failed attempt.
4. Meaning of sensor status bit `0x20`.
5. Left/right order of PC0/PC1 (matters only because the adaptive threshold history is per
   primary button).

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
tools/verify_changes.py   function-level content diff (Ghidra functions only, ~58% coverage)
tools/image_diff.py       whole-image relocation-aware diff (recursive descent, no Ghidra needed)
tools/debounce_sim.py     F-A / F-B debounce model + latency scenarios
tools/debounce_emu.py     runs the real debounce code in Unicorn: scenarios, --fuzz vs the model,
                          --sweep latency tables, --trace replay of a logic-analyzer capture
tools/hidpp_version.py    read-only HID++ version/feature reader with interpretation
tools/hidpp_fake.py       offline self-test of hidpp_version.py against an emulated image
```
