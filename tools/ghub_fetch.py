"""Download firmware/asset packages ("depots") straight from Logitech G HUB's update server.

G HUB's updater (logi_installer_shared.dll) builds its manifest URL as
  {host}/pipeline/v2/update/{appId}/{platform}/{channel}/details.json
with host https://updates.ghub.logitechg.com, appId ghub13, platform win, channel public.
Each depot in details.json has a "url" relative to the host.

Depot container (magic 0x20170110):
  u32 magic | u32 hdr_len | JSON {"files": [{"name", "mode"}]} | per file: u32 len + bytes
Depots with magic 0x20210506 are encrypted (key ids from /pipeline/v2/access/...); not handled.

usage:
  ghub_fetch.py list [REGEX]          list depots (name, size)
  ghub_fetch.py get OUTDIR NAME...    download + unpack depots, e.g. `get dl g502_hero_dfu`
"""
import json
import os
import re
import struct
import sys
import urllib.request

HOST = 'https://updates.ghub.logitechg.com'
MANIFEST = HOST + '/pipeline/v2/update/ghub13/win/public/details.json'
PLAIN_MAGIC = 0x20170110
ENCRYPTED_MAGIC = 0x20210506


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def unpack(data, out):
    magic, n = struct.unpack_from('<II', data, 0)
    if magic == ENCRYPTED_MAGIC:
        raise ValueError('encrypted depot (magic 0x20210506) - not supported')
    if magic != PLAIN_MAGIC:
        raise ValueError(f'unknown depot magic {magic:#x}')
    hdr = json.loads(data[8:8 + n])
    p = 8 + n
    root = os.path.realpath(out)
    for f in hdr['files']:
        (ln,) = struct.unpack_from('<I', data, p)
        p += 4
        dst = os.path.realpath(os.path.join(root, f['name']))
        if not dst.startswith(root + os.sep):
            raise ValueError(f'unsafe path in depot: {f["name"]!r}')
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, 'wb') as fh:
            fh.write(data[p:p + ln])
        p += ln
        print(f'  {ln:10d}  {f["name"]}')


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ('list', 'get'):
        sys.exit(__doc__)
    details = json.loads(fetch(MANIFEST))
    depots = {d['name']: d for d in details['depots']}
    print(f'G HUB {details["version"]} (build {details["buildId"]}), {len(depots)} depots',
          file=sys.stderr)
    if sys.argv[1] == 'list':
        pat = re.compile(sys.argv[2] if len(sys.argv) > 2 else '')
        for name in sorted(depots):
            if pat.search(name):
                print(f'{depots[name]["size"]:12d}  {name}')
        return
    out = sys.argv[2]
    for name in sys.argv[3:]:
        d = depots[name]
        data = fetch(HOST + d['url'])
        if len(data) != d['size']:
            sys.exit(f'{name}: size mismatch {len(data)} != {d["size"]}')
        print(name)
        unpack(data, os.path.join(out, name))


if __name__ == '__main__':
    main()
