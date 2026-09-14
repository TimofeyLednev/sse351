#
# stamp351.py - Rewrite a PE image's version stamps to Windows NT 3.51.
#
# The NT 4.0 DDK hardcodes "-version:4.00 -osversion:4.00" in makefile.def,
# so every binary it links claims to require NT 4.0. This rewrites the
# OperatingSystemVersion, ImageVersion and SubsystemVersion fields in the
# optional header to 3.51 and fixes the PE checksum.
#
# Usage: python stamp351.py <file.sys> [major] [minor]
#
# Runs on Python 2.6+ and 3.x (the DDK-era host may only have an old one).
#

import struct
import sys


def checksum(data, checksum_offset):
    """Compute the PE image checksum the way the NT loader expects."""
    # Sum the file as 16-bit words, skipping the 4 checksum bytes themselves.
    total = 0
    length = len(data)

    # Pad to an even length for the 16-bit walk.
    if length % 2:
        data = data + b'\0'

    for i in range(0, len(data), 2):
        if i == checksum_offset or i == checksum_offset + 2:
            continue
        word = struct.unpack_from('<H', data, i)[0]
        total += word
        total = (total & 0xffff) + (total >> 16)

    total = (total & 0xffff) + (total >> 16)
    total = total & 0xffff
    return (total + length) & 0xffffffff


def stamp(path, major, minor):
    with open(path, 'rb') as f:
        data = bytearray(f.read())

    if data[0:2] != b'MZ':
        raise SystemExit('%s: not an MZ image' % path)

    e_lfanew = struct.unpack_from('<I', bytes(data), 0x3c)[0]
    if bytes(data[e_lfanew:e_lfanew + 4]) != b'PE\0\0':
        raise SystemExit('%s: not a PE image' % path)

    opt = e_lfanew + 4 + 20
    magic = struct.unpack_from('<H', bytes(data), opt)[0]
    if magic != 0x10b:
        raise SystemExit('%s: not PE32 (magic %04x)' % (path, magic))

    # Optional header layout (PE32), offsets from start of optional header:
    #   40 MajorOperatingSystemVersion  42 MinorOperatingSystemVersion
    #   44 MajorImageVersion            46 MinorImageVersion
    #   48 MajorSubsystemVersion        50 MinorSubsystemVersion
    #   64 CheckSum
    before = struct.unpack_from('<HHHHHH', bytes(data), opt + 40)
    print('%s: was OS %d.%02d Image %d.%02d Subsystem %d.%02d' %
          ((path,) + before))

    struct.pack_into('<HHHHHH', data, opt + 40,
                     major, minor, major, minor, major, minor)

    checksum_offset = opt + 64
    struct.pack_into('<I', data, checksum_offset, 0)
    new_checksum = checksum(bytes(data), checksum_offset)
    struct.pack_into('<I', data, checksum_offset, new_checksum)

    after = struct.unpack_from('<HHHHHH', bytes(data), opt + 40)
    print('%s: now OS %d.%02d Image %d.%02d Subsystem %d.%02d, checksum %08x' %
          ((path,) + after + (new_checksum,)))

    with open(path, 'wb') as f:
        f.write(bytes(data))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit('usage: stamp351.py <file.sys> [major] [minor]')
    major = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    minor = int(sys.argv[3]) if len(sys.argv) > 3 else 51
    stamp(sys.argv[1], major, minor)
