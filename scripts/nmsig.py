"""
nmsig.py - Does intlfxsr.sys's #NM signature check pass on NT 3.51?

intlfxsr.sys does not merely *recognise* the kernel's #NM (vector 7) handler --
it replaces it with its own, and the two blobs it carries begin with a
byte-for-byte copy of the kernel handler's prologue. From the decompilation:

    FUN_00010c42(blob_start, blob_end):
        len = blob_end - blob_start
        if RtlCompareMemory(live_idt7_handler, blob_start, len) == len:
            DAT_00010768  = blob_start          # this blob becomes the new handler
            DAT_000106b8 += len                 # resume address = live handler + len
            return TRUE

    entry():
        DAT_000106b8 = <handler address read out of IDT[7]>
        if !FUN_00010c42(0x1034b, 0x10381) and !FUN_00010c42(0x10314, 0x10349):
            fail with error 6

    FUN_00010bb5():  writes DAT_00010768 into IDT[7] on each processor

So the driver's handler is `<verbatim kernel prologue> + <FXSAVE/FXRSTOR work>`
and then it re-enters the kernel handler at `live + len`, just past the prologue
it duplicated. The compare is what guarantees that resume point is valid: if the
kernel's prologue is not the one the blob was built from, the resume offset is
garbage and the driver refuses to load.

Two blobs are carried because two NT 4.0 builds differ by one instruction in
that prologue (`push -1` vs `sub esp,4`).

This script extracts both blobs, pulls the real vector 7 handler out of the
target kernel via findidt, and reports whether either would match -- i.e.
whether the port inherits a working #NM hook or has to re-derive one.

Usage:
    python nmsig.py <intlfxsr.sys> <ntoskrnl.exe>
"""

import struct
import sys
import os

# findidt.py lives next to this script; add its directory to the path so the
# import works regardless of the current working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from findidt import load, rva_to_off, code_ranges, find_idt


BLOBS = [
    (0x1034b, 0x10381, 'variant A (tried first)'),
    (0x10314, 0x10349, 'variant B (tried second)'),
]


def relocs(data, sections, image_base):
    """RVAs touched by the base-relocation table."""
    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    opt = e_lfanew + 4 + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    dd = opt + (96 if magic == 0x10b else 112)
    rva, size = struct.unpack_from('<II', data, dd + 5 * 8)
    if not rva or not size:
        return set()

    off, _ = rva_to_off(sections, rva)
    if off is None:
        return set()

    out = set()
    end = off + size
    while off < end:
        page, block = struct.unpack_from('<II', data, off)
        if block < 8:
            break
        for i in range(off + 8, off + block, 2):
            entry = struct.unpack_from('<H', data, i)[0]
            if entry >> 12 != 0:                # skip IMAGE_REL_BASED_ABSOLUTE
                out.add(page + (entry & 0xfff))
        off += block
    return out


def read_rva(data, sections, base, rva_start, rva_end):
    off, sec = rva_to_off(sections, rva_start - base)
    if off is None:
        raise SystemExit('RVA %08x is not in a raw section' % (rva_start - base))
    return data[off:off + (rva_end - rva_start)], off, sec


def hexdump(blob, va, indent='    '):
    for i in range(0, len(blob), 16):
        print(indent + '%08x  %s'
              % (va + i, ' '.join('%02x' % b for b in blob[i:i + 16])))


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: nmsig.py <intlfxsr.sys> <ntoskrnl.exe>')

    drv_path, krn_path = sys.argv[1], sys.argv[2]

    ddata, dsec, dbase = load(drv_path)
    kdata, ksec, kbase = load(krn_path)

    print('driver : %s  ImageBase %08x' % (drv_path, dbase))
    print('kernel : %s  ImageBase %08x' % (krn_path, kbase))
    print('')

    # --- the kernel's real vector 7 handler -------------------------------
    runs = find_idt(kdata, ksec, kbase)
    if not runs:
        raise SystemExit('no IDT found in %s' % krn_path)
    runs.sort(key=lambda r: -len(r['entries']))
    idt = runs[0]
    kind, nm_va, _ = idt['entries'][7]
    if kind != 'gate':
        raise SystemExit('IDT vector 7 is empty')

    print('IDT template at VA %08x, vector 7 -> %08x' % (kbase + idt['rva'], nm_va))
    print('')

    reloc_rvas = relocs(ddata, dsec, dbase)

    matched = None
    for lo, hi, label in BLOBS:
        length = hi - lo
        blob, boff, bsec = read_rva(ddata, dsec, dbase, lo, hi)
        live, loff, lsec = read_rva(kdata, ksec, kbase, nm_va, nm_va + length)

        # RtlCompareMemory returns the count of leading bytes that agree.
        n = 0
        while n < length and blob[n] == live[n]:
            n += 1

        touched = sorted(r for r in reloc_rvas if lo - dbase <= r < hi - dbase)

        print('=== %s: driver RVA %05x..%05x, %d bytes (%s) ==='
              % (label, lo - dbase, hi - dbase, length, bsec))
        print('  driver blob:')
        hexdump(blob, lo, '      ')
        print('  kernel vector 7 (%s, file %08x):' % (lsec, loff))
        hexdump(live, nm_va, '      ')
        print('  relocations inside the compared range: %s'
              % (', '.join('%05x' % r for r in touched) if touched else 'none'))
        print('  RtlCompareMemory -> %d of %d' % (n, length))
        if n == length:
            print('  MATCH. This blob becomes IDT[7]; resume address = %08x'
                  % (nm_va + length))
            if matched is None:
                matched = (label, length, nm_va + length)
        else:
            print('  no match (first difference at +%d: driver %02x vs kernel %02x)'
                  % (n, blob[n], live[n]))
        print('')

    print('-' * 68)
    if matched:
        label, length, resume = matched
        print('VERDICT: the signature check PASSES on this kernel via %s.' % label)
        print('')
        print('  The NT 3.51 #NM prologue is byte-identical to the NT 4.0 one the')
        print('  driver was built against, so error 6 does not occur and the')
        print('  hardcoded blob can be reused as-is. The driver would resume the')
        print('  kernel handler at %08x (vector 7 + %d).' % (resume, length))
        print('')
        print('  Worth re-checking against the live IDT on the target machine:')
        print('  this compares the on-disk image, and a boot-time patch to the')
        print('  handler would not show up here.')
    else:
        print('VERDICT: the signature check FAILS. Error 6.')
        print('')
        print('  Rebuild the blob from the kernel bytes dumped above: copy the')
        print('  prologue verbatim, append the FXSAVE/FXRSTOR work, and resume at')
        print('  vector 7 + <prologue length>.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
