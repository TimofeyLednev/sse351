#
# checkimports.py - Verify that every symbol a driver imports from
# ntoskrnl.exe / hal.dll actually exists in a given NT 3.51 kernel.
#
# This is the check that decides whether a driver can load at all: the NT
# loader resolves every import by name at load time, and a single missing
# name makes the load fail with STATUS_PROCEDURE_NOT_FOUND (0xC000007A)
# before DriverEntry ever runs.
#
# Usage:
#   python checkimports.py <driver.sys> <ntoskrnl.exe> [hal.dll ...]
#
# Runs on Python 2.6+ and 3.x.
#

import struct
import sys


def load(path):
    with open(path, 'rb') as f:
        data = f.read()

    if data[0:2] != b'MZ':
        raise SystemExit('%s: not an MZ image' % path)

    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\0\0':
        raise SystemExit('%s: not a PE image' % path)

    file_header = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, file_header + 2)[0]
    opt_size = struct.unpack_from('<H', data, file_header + 16)[0]
    opt = file_header + 20

    directories = []
    dir_base = opt + 96
    for i in range(16):
        directories.append(struct.unpack_from('<II', data, dir_base + i * 8))

    sections = []
    sec_base = opt + opt_size
    for i in range(num_sections):
        entry = sec_base + i * 40
        name = struct.unpack_from('<8s', data, entry)[0]
        vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', data, entry + 8)
        sections.append((name.rstrip(b'\0').decode('latin-1'),
                         vaddr, vsize, raddr, rsize))

    def rva_to_offset(rva):
        for name, vaddr, vsize, raddr, rsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return raddr + (rva - vaddr)
        return None

    return data, directories, rva_to_offset


def cstring(data, offset):
    end = data.index(b'\0', offset)
    return data[offset:end].decode('latin-1')


def get_exports(path):
    """Return the set of names exported by a PE image."""
    data, directories, rva_to_offset = load(path)
    rva, size = directories[0]
    if not rva:
        return set()

    offset = rva_to_offset(rva)
    ordinal_base, num_funcs, num_names, func_rva, name_rva, ord_rva = \
        struct.unpack_from('<IIIIII', data, offset + 16)

    names = set()
    name_table = rva_to_offset(name_rva)
    for i in range(num_names):
        entry_rva = struct.unpack_from('<I', data, name_table + i * 4)[0]
        names.add(cstring(data, rva_to_offset(entry_rva)))
    return names


def get_imports(path):
    """Return {dll_name_lower: [imported symbol names]} for a PE image."""
    data, directories, rva_to_offset = load(path)
    rva, size = directories[1]
    if not rva:
        return {}

    result = {}
    offset = rva_to_offset(rva)
    index = 0
    while True:
        entry = offset + index * 20
        orig_thunk, timestamp, forwarder, name_rva, first_thunk = \
            struct.unpack_from('<IIIII', data, entry)
        if orig_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break

        dll = cstring(data, rva_to_offset(name_rva))
        thunk_rva = orig_thunk if orig_thunk else first_thunk
        thunk_offset = rva_to_offset(thunk_rva)

        symbols = []
        j = 0
        while True:
            value = struct.unpack_from('<I', data, thunk_offset + j * 4)[0]
            if value == 0:
                break
            if value & 0x80000000:
                symbols.append('#%d' % (value & 0xffff))
            else:
                # Hint/Name table entry: 2-byte hint then the name.
                symbols.append(cstring(data, rva_to_offset(value) + 2))
            j += 1

        result.setdefault(dll.lower(), []).extend(symbols)
        index += 1

    return result


def main():
    if len(sys.argv) < 3:
        raise SystemExit(
            'usage: checkimports.py <driver.sys> <ntoskrnl.exe> [hal.dll ...]')

    driver = sys.argv[1]
    imports = get_imports(driver)

    # Build one combined export set from every reference image supplied.
    available = {}
    for ref in sys.argv[2:]:
        names = get_exports(ref)
        available[ref] = names
        print('%s: %d exports' % (ref, len(names)))

    combined = set()
    for names in available.values():
        combined |= names

    print('')
    missing_total = 0
    for dll in sorted(imports):
        symbols = sorted(set(imports[dll]))
        missing = [s for s in symbols if s not in combined]
        status = 'OK' if not missing else 'MISSING %d' % len(missing)
        print('%s: %d imports  [%s]' % (dll, len(symbols), status))
        for symbol in symbols:
            mark = ' ' if symbol in combined else '!'
            print('   %s %s' % (mark, symbol))
        missing_total += len(missing)

    print('')
    if missing_total:
        print('RESULT: %d symbol(s) unavailable - this driver will NOT load '
              '(STATUS_PROCEDURE_NOT_FOUND).' % missing_total)
        return 1

    print('RESULT: all imports resolve. Driver can load.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
