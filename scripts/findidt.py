"""
findidt.py - Recover the IDT and its trap handlers from an NT/i386 kernel image.

Why the obvious approaches fail
-------------------------------
1. Scanning for `push 0 / push <vector> / jmp common` finds nothing. NT does not
   use per-vector stubs that jump to a shared handler; it *inlines* the whole
   trap-frame setup (the ENTER_TRAP macro) at the top of every handler.

2. Scanning for i386 gate descriptors finds nothing either. A real gate splits
   the handler address into two halves:

       +0 USHORT Offset          address bits 15..0
       +2 USHORT Selector        0x0008 = KGDT_R0_CODE
       +4 UCHAR  Reserved        0
       +5 UCHAR  Access          0x8E = 32-bit int gate DPL0, 0xEE = DPL3
       +6 USHORT ExtendedOffset  address bits 31..16

   MASM cannot emit a split flat offset at assembly time, so the kernel ships
   the table *unswizzled*, as a plain array of:

       dd  offset handler        full 32-bit address
       dw  8E00h                 access, already in the high byte
       dw  8                     selector

   `KiInitializeIdt` walks this at boot and shuffles the halves into place. So
   in the on-disk image the table is 8-byte records of that second shape, and
   that is what this script looks for. It handles the swizzled form too, in
   case you point it at a memory dump.

Record index == vector number, so this gives the handlers *by vector* instead of
by guesswork. For the NT 3.51 SSE port the two that matter are:

  * vector 7  #NM  device-not-available - the handler intlfxsr.sys repoints.
    Before repointing, the driver RtlCompareMemory's the live handler against
    NT 4.0 prologue bytes baked into the driver image. On NT 3.51 those bytes
    turn out to match verbatim (vector 7 = 8013a930, 54 bytes identical to the
    driver's variant A blob), so no rebuild is needed - see nmsig.py.
  * vector 19 #XM  SIMD floating-point - if this shares the catch-all stub,
    3.51 has no real #XM handler and CR4.OSXMMEXCPT must stay clear. It does:
    8013c10c, shared by 16 vectors.

Usage:
    python findidt.py <ntoskrnl.exe> [vector ...]      # default: 7 and 19
"""

import struct
import sys


VECTOR_NAMES = {
    0:  '#DE divide error',            1:  '#DB debug',
    2:  'NMI',                         3:  '#BP breakpoint',
    4:  '#OF overflow',                5:  '#BR bound range',
    6:  '#UD invalid opcode',          7:  '#NM device not available',
    8:  '#DF double fault',            9:  'coprocessor segment overrun',
    10: '#TS invalid TSS',             11: '#NP segment not present',
    12: '#SS stack fault',             13: '#GP general protection',
    14: '#PF page fault',              15: 'reserved',
    16: '#MF x87 floating-point',      17: '#AC alignment check',
    18: '#MC machine check',           19: '#XM SIMD floating-point',
    0x2A: 'KiGetTickCount',            0x2B: 'KiCallbackReturn',
    0x2C: 'KiSetLowWaitHighThread',    0x2D: 'KiDebugService',
    0x2E: 'KiSystemService',           0x2F: 'reserved',
}

ACCESS_OK = (0x8E00, 0xEE00, 0x8F00, 0xEF00, 0x8500, 0xE500)
R0_CODE = 0x0008


def load(path):
    with open(path, 'rb') as f:
        data = f.read()

    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    file_header = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, file_header + 2)[0]
    opt_size = struct.unpack_from('<H', data, file_header + 16)[0]
    opt = file_header + 20
    image_base = struct.unpack_from('<I', data, opt + 28)[0]

    sections = []
    sec_base = opt + opt_size
    for i in range(num_sections):
        entry = sec_base + i * 40
        name = struct.unpack_from('<8s', data, entry)[0].rstrip(b'\0')
        vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', data, entry + 8)
        chars = struct.unpack_from('<I', data, entry + 36)[0]
        sections.append({'name': name.decode('latin-1'),
                         'vaddr': vaddr, 'vsize': vsize,
                         'raddr': raddr, 'rsize': rsize, 'chars': chars})
    return data, sections, image_base


def rva_to_off(sections, rva):
    for s in sections:
        if not s['rsize']:
            continue
        if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rsize']):
            delta = rva - s['vaddr']
            if delta < s['rsize']:
                return s['raddr'] + delta, s['name']
    return None, None


def code_ranges(sections, image_base):
    out = []
    for s in sections:
        if s['chars'] & 0x20000000 and s['rsize']:      # IMAGE_SCN_MEM_EXECUTE
            lo = image_base + s['vaddr']
            out.append((lo, lo + max(s['vsize'], s['rsize']), s['name']))
    return out


def in_code(ranges, va):
    return any(lo <= va < hi for lo, hi, _ in ranges)


def record_at(blob, off, ranges):
    """Decode one 8-byte IDT record in either the template or swizzled form."""
    if off + 8 > len(blob):
        return None

    addr, access, selector = struct.unpack_from('<IHH', blob, off)

    # Template form: dd handler / dw access / dw selector.
    if selector == R0_CODE:
        if addr == 0 and access == 0:
            return ('empty', 0, 0)
        if access in ACCESS_OK and in_code(ranges, addr):
            return ('gate', addr, access >> 8)

    # Already-swizzled real gate descriptor.
    lo, sel, resv, acc, hi = struct.unpack_from('<HHBBH', blob, off)
    if sel == R0_CODE and resv == 0 and (acc << 8) in ACCESS_OK:
        va = (hi << 16) | lo
        if in_code(ranges, va):
            return ('gate', va, acc)

    return None


def find_idt(data, sections, image_base, min_run=24):
    ranges = code_ranges(sections, image_base)
    runs = []

    for s in sections:
        if not s['rsize']:
            continue
        blob = data[s['raddr']:s['raddr'] + s['rsize']]

        off = 0
        while off + 8 <= len(blob):
            first = record_at(blob, off, ranges)
            if first is None or first[0] == 'empty':
                off += 1
                continue

            entries = []
            cur = off
            while cur + 8 <= len(blob):
                r = record_at(blob, cur, ranges)
                if r is None:
                    break
                entries.append(r)
                cur += 8

            while entries and entries[-1][0] == 'empty':
                entries.pop()

            if len(entries) >= min_run:
                runs.append({'section': s['name'],
                             'file_off': s['raddr'] + off,
                             'rva': s['vaddr'] + off,
                             'entries': entries})
                off += len(entries) * 8
            else:
                off += 1

    return runs


def dump_handler(data, sections, image_base, va, length=80, indent='        '):
    off, sec = rva_to_off(sections, va - image_base)
    if off is None:
        print(indent + '(VA %08x is not in a raw section)' % va)
        return None
    blob = data[off:off + length]
    print(indent + 'section %s, file offset %08x' % (sec, off))
    for i in range(0, len(blob), 16):
        print(indent + '%08x  %s'
              % (va + i, ' '.join('%02x' % b for b in blob[i:i + 16])))
    return blob


def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: findidt.py <ntoskrnl.exe> [vector ...]')

    path = sys.argv[1]
    wanted = [int(a, 0) for a in sys.argv[2:]] or [7, 19]

    data, sections, image_base = load(path)
    print('%s: ImageBase %08x' % (path, image_base))
    for lo, hi, name in code_ranges(sections, image_base):
        print('  executable: %-8s %08x - %08x' % (name, lo, hi))
    print('')

    runs = find_idt(data, sections, image_base)
    if not runs:
        print('No IDT-shaped run found.')
        return 1

    runs.sort(key=lambda r: -len(r['entries']))
    idt = runs[0]
    print('IDT template: %s, VA %08x (file %08x), %d vectors'
          % (idt['section'], image_base + idt['rva'], idt['file_off'],
             len(idt['entries'])))
    print('')

    counts = {}
    for kind, va, _ in idt['entries']:
        if kind == 'gate':
            counts[va] = counts.get(va, 0) + 1
    shared = set(va for va, n in counts.items() if n > 1)

    print('vec       handler   DPL  note')
    for i, (kind, va, access) in enumerate(idt['entries']):
        if kind == 'empty':
            continue
        dpl = 3 if (access & 0x60) == 0x60 else 0
        note = VECTOR_NAMES.get(i, '')
        if va in shared:
            note = (note + '  [shared catch-all x%d]' % counts[va]).strip()
        print('  %3d/%02x  %08x   %d    %s' % (i, i, va, dpl, note))
    print('')

    for v in wanted:
        if v >= len(idt['entries']) or idt['entries'][v][0] == 'empty':
            print('vector %d: not present in the table' % v)
            print('')
            continue
        _, va, _ = idt['entries'][v]
        tag = '   [SHARED catch-all - no dedicated handler]' if va in shared else ''
        print('vector %d (%s) -> %08x%s'
              % (v, VECTOR_NAMES.get(v, ''), va, tag))
        dump_handler(data, sections, image_base, va)
        print('')

    return 0


if __name__ == '__main__':
    sys.exit(main())
