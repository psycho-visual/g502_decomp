#!/usr/bin/env python3
"""Read-only firmware/bootloader version reader for Logitech mice (HID++ 2.0).

Purpose: find out what a given (especially a *newer*) G502 HERO actually runs, so we can
tell whether new units use the same firmware/bootloader as the images in this repo
(F-A 127.01.07 / F-B 127.03.10) or something different. It only *reads* from the device:
USB IDs, and the HID++ Root (0x0000), FeatureSet (0x0001), Device Information (0x0003) and
Device Name (0x0005) "get" functions. It never writes settings or firmware.

What it prints per device:
  * USB vendor:product id, bcdDevice ("rel"), product string (OS HID enumeration)
  * HID++ getDeviceInfo: entity count, transport, modelId, extendedModelId
    (unitId is a per-unit serial - the STM32 unique ID - so it is hidden unless
    --show-unit-id is given; leave it hidden when posting output publicly)
  * every firmware entity: type, name+version in Logitech's form (e.g. U127.03_B0010),
    the PID that entity reports, and which one is active
  * the HID++ feature list
  * an interpretation against what F-A/F-B are known to report (all values below were
    read out of the two firmware images; see README "What the mouse reports")

Requires hidapi:  pip install hidapi      (Windows wheels bundle the DLL)
Usage:
  python hidpp_version.py            # scan all Logitech HID++ interfaces
  python hidpp_version.py --all      # also try non-HID++-looking 046d interfaces
  python hidpp_version.py --path PATH # target one interface (path from --list)
  python hidpp_version.py --list      # just enumerate 046d HID interfaces
  python hidpp_version.py -v          # dump every raw HID++ exchange
"""
import argparse
import sys
import time

LOGITECH_VID = 0x046D
SW_ID = 0x05  # nonzero software id so replies are distinguishable from notifications

SHORT_REPORT = 0x10  # 7 bytes total:  id, dev, feat, func|sw, p0..p2
LONG_REPORT = 0x11   # 20 bytes total: id, dev, feat, func|sw, p0..p15
REPORT_LEN = {SHORT_REPORT: 7, LONG_REPORT: 20}

ROOT_FEATURE = 0x0000
FEATURE_SET = 0x0001
FEATURE_DEVICE_INFO = 0x0003
FEATURE_DEVICE_NAME = 0x0005

# ---- What F-A / F-B report, read out of the images (handlers at F-B 0x08005aec / 0x0800c200,
# feature table at F-B 0x0800caa8, USB device descriptor). Identical in both except versions.
G502_HERO_PID = 0xC08B          # normal mode (app)
G502_HERO_BOOT_PID = 0xAAE6     # bootloader / DFU mode (also listed in G HUB's dfu.json)
KNOWN_APPS = {                  # (name, number, revision, build) of fw entity 0
    ('U1', 0x27, 0x01, 0x0007): 'F-A 127.01.07 (standalone 2019 updater; 2-sample release)',
    ('U1', 0x27, 0x03, 0x0010): 'F-B 127.03.10 (G HUB "improved debouncing"; slow release)',
}
KNOWN_BCD_DEVICE = {0x2701: 'F-A 127.01.07', 0x2703: 'F-B 127.03.10'}
# Entity 1 as F-A/F-B report it: name "BOT" and 81.00 are constants in the *app*; only the
# build (BCD of ASCII digits at bootloader flash 0x08003FF6/8/A/C) comes from the bootloader.
APP_REPORTED_BOOT = ('BOT', 0x81, 0x00)
EXPECTED_FEATURES = {0x0003: 2, 0x0005: 3, 0x1300: 8, 0x2201: 4, 0x8060: 3, 0x8100: 13,
                     0x8110: 5, 0x00C2: 2}
EXPECTED_HIDDEN = {0x18A1: 3, 0x1E00: 2, 0x1E22: 4, 0x1EB0: 4, 0x1801: 2, 0x1802: 1,
                   0x1806: 6, 0x18B1: 1}
FEATURE_NAMES = {0x0000: 'Root', 0x0001: 'FeatureSet', 0x0003: 'DeviceInfo', 0x0005: 'DeviceName',
                 0x00C0: 'DfuControl', 0x00C1: 'DfuControl', 0x00C2: 'DfuControl',
                 0x00C3: 'SecureDfuControl', 0x00D0: 'Dfu', 0x1300: 'LedControl',
                 0x1801: 'Manufacturing', 0x1802: 'DeviceReset', 0x1806: 'DeviceProperties',
                 0x18A1: 'LedSwControl', 0x1E00: 'EnableHiddenFeatures', 0x1EB0: 'TdeAccess',
                 0x1F1F: 'FirmwareProperties', 0x2201: 'AdjustableDpi', 0x8060: 'ReportRate',
                 0x8100: 'OnboardProfiles', 0x8110: 'MouseButtonSpy'}
OLD_UPDATER_DFU = (0x00C0, 0x00C1, 0x00C2)   # the only DFU-control features 127.1.7 speaks
# Probed by ID when the device has no FeatureSet (0x0001)
PROBE_IDS = sorted(set(EXPECTED_FEATURES) | set(EXPECTED_HIDDEN) |
                   {0x0001, 0x00C0, 0x00C1, 0x00C3, 0x00D0, 0x1F1F, 0x1B04, 0x2205, 0x8070,
                    0x8071})

FW_TYPES = {0: 'main application', 1: 'bootloader', 2: 'hardware', 3: 'touchpad',
            4: 'optical sensor', 5: 'SoftDevice'}


class HidppError(Exception):
    def __init__(self, code):
        self.code = code
        names = {1: 'unknown', 2: 'invalid argument', 3: 'out of range', 5: 'invalid feature',
                 7: 'invalid function', 9: 'busy', 0x0a: 'unsupported'}
        super().__init__(f'HID++ error {code} ({names.get(code, "?")})')


def _import_hid():
    try:
        import hid
        return hid
    except ImportError:
        sys.exit("This tool needs the 'hidapi' package.\n"
                 "  pip install hidapi\n"
                 "(On Windows the wheel bundles hidapi.dll; on Linux you may need libhidapi.)")


class Device:
    """One opened HID++ interface, with the device index and report type auto-detected."""

    def __init__(self, hid, path, verbose=False):
        self.h = hid.device()
        self.h.open_path(path)
        self.h.set_nonblocking(False)
        self.verbose = verbose
        self.dev_index = None
        self.report = None

    def close(self):
        try:
            self.h.close()
        except Exception:
            pass

    def _raw(self, report, dev, feat, func_sw, params):
        n = REPORT_LEN[report]
        buf = bytes([report, dev, feat, func_sw]) + bytes(params)
        buf = buf[:n] + bytes(max(0, n - len(buf)))
        if self.verbose:
            print('    >>', buf.hex())
        self.h.write(buf)
        deadline = time.time() + 1.0
        while time.time() < deadline:
            data = self.h.read(20, timeout_ms=400)
            if not data:
                continue
            data = bytes(data)
            if self.verbose:
                print('    <<', data.hex())
            if data[0] not in (SHORT_REPORT, LONG_REPORT) or data[1] != dev:
                continue  # not a HID++ reply for this device index (e.g. a notification)
            if data[2] == 0xFF and data[3] == func_sw:      # HID++ 2.0 error
                raise HidppError(data[5])
            if data[2] == 0x8F:                              # HID++ 1.0 error
                raise HidppError(data[4])
            if data[2] == feat and data[3] == func_sw:
                return data
        raise TimeoutError('no HID++ reply')

    def call(self, feat_index, function, params=(), want_long=True):
        func_sw = ((function & 0x0F) << 4) | SW_ID
        report = self.report or (LONG_REPORT if want_long else SHORT_REPORT)
        return self._raw(report, self.dev_index, feat_index, func_sw, params)

    def ping(self):
        """Find a device index + a working report type by pinging the Root feature."""
        marker = 0x5A
        for dev in (0xFF, 0x01, 0x00):
            for report in (LONG_REPORT, SHORT_REPORT):
                try:
                    r = self._raw(report, dev, ROOT_FEATURE, (0x01 << 4) | SW_ID,
                                  [0, 0, marker])
                except (TimeoutError, OSError, ValueError):
                    continue
                except HidppError:
                    continue
                if r[6] == marker:
                    self.dev_index, self.report = dev, report
                    return r[4], r[5]  # protocol major, minor
        return None

    def get_feature(self, feature_id):
        """(index, type flags, version); index 0 = not supported."""
        r = self.call(ROOT_FEATURE, 0, [(feature_id >> 8) & 0xFF, feature_id & 0xFF, 0])
        return r[4], r[5], r[6]

    def feature_list(self):
        """[(id, flags, version)] via FeatureSet, or by probing PROBE_IDS if it is absent."""
        out = []
        fs = self.get_feature(FEATURE_SET)[0]
        if fs:
            count = self.call(fs, 0)[4]
            for i in range(count + 1):
                r = self.call(fs, 1, [i, 0, 0])
                out.append(((r[4] << 8) | r[5], r[6], r[7]))
            return out, 'FeatureSet'
        for fid in PROBE_IDS:
            idx, flags, ver = self.get_feature(fid)
            if idx:
                out.append((fid, flags, ver))
        return out, 'probe'

    def device_info(self, idx):
        r = self.call(idx, 0)
        info = {'entity_count': r[4]}
        if len(r) >= 20:
            info['unit_id'] = r[5:9].hex()
            info['transport'] = r[9:11].hex()
            info['model_id'] = r[11:17].hex()
            info['extended_model_id'] = r[17]
            info['capabilities'] = r[18]
        return info

    def fw_info(self, idx, entity):
        r = self.call(idx, 1, [entity, 0, 0])
        name = bytes(b for b in r[5:8] if 32 <= b < 127).decode('ascii', 'replace').rstrip()
        b_num, b_rev = r[8], r[9]
        build = (r[10] << 8) | r[11]
        lead = name[-1] if name[-1:].isdigit() else ''      # "U1" + "27" -> 127.03.10
        return {
            'type': FW_TYPES.get(r[4] & 0x0F, f'type {r[4] & 0x0F}'),
            'name': name, 'number': b_num, 'revision': b_rev, 'build': build,
            'combined': f'{name}{b_num:02X}.{b_rev:02X}_B{build:04X}',
            'version': f'{lead}{b_num:02X}.{b_rev:02X}.{build & 0xFF:02X}',
            'active': bool(r[12] & 1) if len(r) > 12 else None,
            'pid': (r[13] << 8) | r[14] if len(r) > 14 else None,
            'raw': bytes(r[4:20]).hex(),
        }

    def device_name(self, idx):
        try:
            length = self.call(idx, 0)[4]
            out = b''
            while len(out) < length:
                r = self.call(idx, 1, [len(out), 0, 0])
                chunk = bytes(r[4:4 + min(16, length - len(out))])
                if not chunk:
                    break
                out += chunk
            return out.decode('ascii', 'replace')
        except (HidppError, TimeoutError, OSError):
            return None


def looks_like_hidpp(d):
    up = d.get('usage_page') or 0
    return up >= 0xFF00


def enumerate_devices(hid, include_all):
    devs = [d for d in hid.enumerate(LOGITECH_VID, 0)]
    cand = [d for d in devs if looks_like_hidpp(d)]
    if include_all or not cand:
        cand = devs
    # de-dup by path
    seen, out = set(), []
    for d in cand:
        if d['path'] not in seen:
            seen.add(d['path'])
            out.append(d)
    return out


def report_device(hid, d, verbose, show_unit_id=False):
    path = d['path']
    pstr = (d.get('product_string') or '').strip()
    usb = {'pid': d['product_id'], 'rel': d.get('release_number', 0)}
    print(f"\n=== {d['vendor_id']:04x}:{d['product_id']:04x}  rel {usb['rel']:04x}"
          f"  {pstr}")
    print(f"    path: {path.decode(errors='replace') if isinstance(path, bytes) else path}"
          f"   usage_page {d.get('usage_page', 0):#06x}")
    dev = None
    try:
        dev = Device(hid, path, verbose)
    except Exception as e:
        print(f"    could not open: {e}")
        return
    try:
        proto = dev.ping()
        if not proto:
            print("    no HID++ response on this interface (not the HID++ collection, or "
                  "needs another device index)")
            return
        print(f"    HID++ {proto[0]}.{proto[1]}  (device index {dev.dev_index:#04x},"
              f" report {dev.report:#04x})")
        name = None
        ni = dev.get_feature(FEATURE_DEVICE_NAME)[0]
        if ni:
            name = dev.device_name(ni)
        if name:
            print(f"    device name: {name}")
        info, entities, features = None, [], None
        di = dev.get_feature(FEATURE_DEVICE_INFO)[0]
        if not di:
            print("    feature 0x0003 (Device Information) not present")
        else:
            info = dev.device_info(di)
            shown = dict(info)
            shown.pop('entity_count')
            if not show_unit_id and 'unit_id' in shown:
                shown['unit_id'] = '<hidden, --show-unit-id>'
            print('    ' + '  '.join(f'{k}={v}' for k, v in shown.items()))
            print(f"    firmware entities: {info['entity_count']}")
            for e in range(info['entity_count']):
                try:
                    fi = dev.fw_info(di, e)
                except (HidppError, TimeoutError, OSError) as ex:
                    print(f"      [{e}] <{ex}>")
                    continue
                entities.append(fi)
                star = '*' if fi['active'] else ' '
                pid = f"{fi['pid']:04X}" if fi['pid'] is not None else '?'
                print(f"      [{e}]{star} {fi['type']:<16} {fi['combined']:<16}"
                      f" ({fi['version']})  pid {pid}  raw {fi['raw']}")
        try:
            features, how = dev.feature_list()
            print(f"    features ({how}, flags 0x40 = hidden, 0x20 = engineering):")
            for fid, flags, ver in features:
                print(f"      {fid:#06x} v{ver:<3d} flags {flags:#04x}  {FEATURE_NAMES.get(fid, '')}")
        except (HidppError, TimeoutError, OSError) as ex:
            print(f"    feature list unavailable: {ex}")
        print('    interpretation:')
        for line in interpret(usb, info, entities, features):
            print('      - ' + line)
    except (TimeoutError, OSError) as e:
        print(f"    communication failed: {e}")
    finally:
        dev.close()


def interpret(usb, info, entities, features):
    """Compare what the device reports with what F-A / F-B report (see constants above)."""
    out = []
    pid, rel = usb['pid'], usb['rel']
    if pid == G502_HERO_BOOT_PID:
        out.append('USB PID AAE6: the mouse is in bootloader (DFU) mode, not running its app.')
    elif pid != G502_HERO_PID:
        out.append(f'USB PID {pid:04X} is not C08B: the 127.1.7 updater only reacts to C08B '
                   f'(normal) and AAE6 (bootloader) and would ignore this device.')
    if pid == G502_HERO_PID:
        out.append(f'USB bcdDevice {rel:04X}: ' + KNOWN_BCD_DEVICE.get(
            rel, 'not a revision F-A/F-B report (they report 2701 / 2703)'))
    app = next((e for e in entities if e['type'] == 'main application'), None)
    boot = next((e for e in entities if e['type'] == 'bootloader'), None)
    known = None
    if app:
        known = KNOWN_APPS.get((app['name'], app['number'], app['revision'], app['build']))
        if known:
            out.append(f"main app {app['combined']} = {known}")
        else:
            out.append(f"main app {app['combined']} is NOT F-A or F-B: this unit runs firmware "
                       f"that is not in this repo (\"F-C\"); G HUB only serves F-B.")
        if app['pid'] not in (None, G502_HERO_PID):
            out.append(f"main app entity reports PID {app['pid']:04X} (F-A/F-B report C08B)")
        minor = int(f"{app['revision']:02X}") if f"{app['revision']:02X}".isdigit() else 0
        build = int(f"{app['build'] & 0xFF:02X}") if f"{app['build'] & 0xFF:02X}".isdigit() else 0
        if (minor << 16 | build) >= 0x10007:
            out.append('127.1.7 updater gate: version >= x.01.07, so without /FORCE it stops '
                       'at "No update is needed" (true for F-B too, old or new unit).')
    if boot:
        bpid = f"{boot['pid']:04X}" if boot['pid'] is not None else '?'
        if known and (boot['name'], boot['number'], boot['revision']) == APP_REPORTED_BOOT:
            out.append(f"bootloader {boot['combined']} pid {bpid}: name and 81.00 are constants "
                       f"in the F-A/F-B app; only the build B{boot['build']:04X} is read from "
                       f"the bootloader. Compare that build with an older unit.")
        else:
            out.append(f"bootloader {boot['combined']} pid {bpid}: reported by an unknown app, "
                       f"so every field may differ in meaning from F-A/F-B.")
        if boot['pid'] not in (None, G502_HERO_BOOT_PID):
            out.append(f'bootloader PID {bpid} is not AAE6: the 127.1.7 updater would not '
                       f'recognise the mouse once it reboots into DFU mode.')
    if info:
        if info['entity_count'] != 2:
            out.append(f"{info['entity_count']} firmware entities (F-A/F-B report 2)")
        if info.get('model_id') and info['model_id'] != 'c08b00000000':
            out.append(f"modelId {info['model_id']} (F-A/F-B report c08b00000000)")
        if 'extended_model_id' in info:
            out.append(f"extendedModelId {info['extended_model_id']}: F-A/F-B read this from a "
                       f"factory-written, CRC-checked EEPROM byte (0x08080170); a different value "
                       f"than older units marks a hardware variant.")
    if features is not None:
        have = {fid: ver for fid, _, ver in features}
        missing = [f'{f:#06x}' for f in EXPECTED_FEATURES if f not in have]
        changed = [f'{f:#06x} v{have[f]} (F-A/F-B v{v})' for f, v in EXPECTED_FEATURES.items()
                   if f in have and have[f] != v]
        extra = [f'{f:#06x}' for f in have
                 if f not in EXPECTED_FEATURES and f not in EXPECTED_HIDDEN and f > 0x0001]
        if not (missing or changed or extra):
            out.append('feature set matches F-A/F-B')
        for label, lst in (('missing vs F-A/F-B', missing), ('version differs', changed),
                           ('not in F-A/F-B', extra)):
            if lst:
                out.append(f"features {label}: {', '.join(lst)}")
        dfu = [f for f in have if f in OLD_UPDATER_DFU]
        if 0x00C3 in have and not dfu:
            out.append('DFU control is 0x00C3 (secure DFU) only: the 127.1.7 updater speaks '
                       '0x00C0/C1/C2 and cannot put this unit into its bootloader.')
        elif not dfu and pid == G502_HERO_PID:
            out.append('no DFU-control feature the 127.1.7 updater understands (0x00C0/C1/C2)')
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--list', action='store_true', help='just list 046d HID interfaces')
    ap.add_argument('--all', action='store_true',
                    help='try every 046d interface, not only HID++-looking ones')
    ap.add_argument('--path', help='target a single interface path (from --list)')
    ap.add_argument('-v', '--verbose', action='store_true', help='dump raw HID++ exchanges')
    ap.add_argument('--show-unit-id', action='store_true',
                    help='print the per-unit serial (unitId); hidden by default')
    args = ap.parse_args()

    hid = _import_hid()

    if args.list:
        for d in hid.enumerate(LOGITECH_VID, 0):
            path = d['path']
            print(f"{d['vendor_id']:04x}:{d['product_id']:04x} usage_page={d.get('usage_page', 0):#06x}"
                  f" if={d.get('interface_number', -1)}"
                  f" {(d.get('product_string') or '').strip()}"
                  f"  {path.decode(errors='replace') if isinstance(path, bytes) else path}")
        return

    if args.path:
        p = args.path.encode() if not isinstance(args.path, bytes) else args.path
        for d in hid.enumerate(LOGITECH_VID, 0):
            if d['path'] == p:
                report_device(hid, d, args.verbose, args.show_unit_id)
                return
        sys.exit(f"path not found among 046d devices: {args.path}")

    devs = enumerate_devices(hid, args.all)
    if not devs:
        sys.exit("No Logitech (046d) HID devices found. Is the mouse plugged in?")
    print(f"Found {len(devs)} candidate interface(s). Reading versions (read-only)...")
    for d in devs:
        report_device(hid, d, args.verbose, args.show_unit_id)


if __name__ == '__main__':
    main()
