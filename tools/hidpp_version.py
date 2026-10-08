#!/usr/bin/env python3
"""Read-only firmware/bootloader version reader for Logitech mice (HID++ 2.0).

Purpose: find out what a given (especially a *newer*) G502 HERO actually runs, so we can
tell whether new units use the same firmware/bootloader as the images in this repo
(F-A 127.01.07 / F-B 127.03.10) or something different. It only *reads* from the device
(USB IDs + the HID++ "Device Information" feature 0x0003); it never writes settings or
firmware.

What it prints per device:
  * USB vendor:product id, release number, product string (from the OS HID enumeration)
  * modelId / unitId (HID++ getDeviceInfo)
  * every firmware entity: type (main app / bootloader / hardware), ASCII name prefix,
    version, build, the PID that entity reports, and which one is active

Compare the "main application" line against F-A `U127.01_B0007` / F-B `U127.03_B0010`, and
note the bootloader entity's version — a newer bootloader is the prime suspect for why the
old downgrade no longer works.

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
FEATURE_DEVICE_INFO = 0x0003
FEATURE_DEVICE_NAME = 0x0005

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
        r = self.call(ROOT_FEATURE, 0, [(feature_id >> 8) & 0xFF, feature_id & 0xFF, 0])
        return r[4]  # feature index, 0 = not supported

    def device_info(self, idx):
        r = self.call(idx, 0)
        info = {'entity_count': r[4]}
        if len(r) >= 20:
            info['unit_id'] = r[5:9].hex()
            info['transport'] = r[9:11].hex()
            info['model_id'] = r[11:17].hex()
        return info

    def fw_info(self, idx, entity):
        r = self.call(idx, 1, [entity, 0, 0])
        name = bytes(b for b in r[5:8] if 32 <= b < 127).decode('ascii', 'replace')
        b_num, b_rev = r[8], r[9]
        build = (r[10] << 8) | r[11]
        return {
            'type': FW_TYPES.get(r[4] & 0x0F, f'type {r[4] & 0x0F}'),
            'name': name,
            'combined': f'{name}{b_num:02X}.{b_rev:02X}_B{build:04X}',
            'version': f'{b_num:02X}.{b_rev:02X}.{build & 0xFF:02X}',
            'active': bool(r[12] & 1) if len(r) > 12 else None,
            'pid': f'{r[13]:02X}{r[14]:02X}' if len(r) > 14 else None,
            'raw': r[4:16].hex(),
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


def report_device(hid, d, verbose):
    path = d['path']
    pstr = (d.get('product_string') or '').strip()
    print(f"\n=== {d['vendor_id']:04x}:{d['product_id']:04x}  rel {d.get('release_number', 0):04x}"
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
        ni = dev.get_feature(FEATURE_DEVICE_NAME)
        if ni:
            name = dev.device_name(ni)
        if name:
            print(f"    device name: {name}")
        di = dev.get_feature(FEATURE_DEVICE_INFO)
        if not di:
            print("    feature 0x0003 (Device Information) not present")
            return
        info = dev.device_info(di)
        extra = '  '.join(f'{k}={v}' for k, v in info.items() if k != 'entity_count')
        print(f"    {extra}")
        print(f"    firmware entities: {info['entity_count']}")
        for e in range(info['entity_count']):
            try:
                fi = dev.fw_info(di, e)
            except (HidppError, TimeoutError, OSError) as ex:
                print(f"      [{e}] <{ex}>")
                continue
            star = '*' if fi['active'] else ' '
            print(f"      [{e}]{star} {fi['type']:<16} {fi['combined']:<18}"
                  f" ver {fi['version']}  pid {fi['pid']}  raw {fi['raw']}")
        print("    (* = active; compare main application to F-A U127.01_B0007 / "
              "F-B U127.03_B0010)")
    except (TimeoutError, OSError) as e:
        print(f"    communication failed: {e}")
    finally:
        dev.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--list', action='store_true', help='just list 046d HID interfaces')
    ap.add_argument('--all', action='store_true',
                    help='try every 046d interface, not only HID++-looking ones')
    ap.add_argument('--path', help='target a single interface path (from --list)')
    ap.add_argument('-v', '--verbose', action='store_true', help='dump raw HID++ exchanges')
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
                report_device(hid, d, args.verbose)
                return
        sys.exit(f"path not found among 046d devices: {args.path}")

    devs = enumerate_devices(hid, args.all)
    if not devs:
        sys.exit("No Logitech (046d) HID devices found. Is the mouse plugged in?")
    print(f"Found {len(devs)} candidate interface(s). Reading versions (read-only)...")
    for d in devs:
        report_device(hid, d, args.verbose)


if __name__ == '__main__':
    main()
