"""Turn a G502 HERO firmware container into a raw application image for analysis.

Accepts either
  * a .dfu file (from the G HUB depot `g502_hero_dfu`), or
  * the old standalone updater .exe (the image is the PE resource type "FIRMWARE").

.dfu layout (big-endian fields in the record header):
  0x00  u8 0, u8 1, "U127_D1" (entity name, NUL padded to 0x10)
  0x10  u8 record type (1 = data), u32 load address (0x08004000), u32 length (0xaf00)
  0x20  image (length bytes)
  ...   record type 2 + 256-byte block (looks like an RSA-2048 signature), record type 3 (end)

usage: fw_extract.py INPUT OUT.bin
"""
import struct
import sys


def dfu_from_exe(path):
    import pefile
    pe = pefile.PE(path)
    for typ in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(typ.name) != 'FIRMWARE':
            continue
        for ent in typ.directory.entries:
            for lang in ent.directory.entries:
                ds = lang.data.struct
                return pe.get_data(ds.OffsetToData, ds.Size)
    sys.exit('no FIRMWARE resource found')


def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, 'rb').read()
    if data[:2] == b'MZ':
        data = dfu_from_exe(src)
    name = data[2:0x10].split(b'\0')[0].decode()
    rtype = data[0x10]
    addr, length = struct.unpack('>II', data[0x11:0x19])
    if rtype != 1:
        sys.exit(f'unexpected first record type {rtype}')
    image = data[0x20:0x20 + length]
    trailer = data[0x20 + length:]
    sp, reset = struct.unpack_from('<II', image, 0)
    ver = image.find(b'U127.')
    print(f'entity {name}  load {addr:#010x}  length {length:#x}  SP {sp:#x}  reset {reset:#x}')
    if ver >= 0:
        print('version string', image[ver:image.index(b'\0', ver)].decode())
    print(f'trailer {len(trailer)} bytes (record types {trailer[0]}, {trailer[-16]})')
    with open(dst, 'wb') as fh:
        fh.write(image)


if __name__ == '__main__':
    main()
