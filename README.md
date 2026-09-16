# nt351sse — SSE / SSE2 / MMX for Windows NT 3.51

A kernel driver that enables **SSE, SSE2 and MMX** on **Windows NT 3.51**, an OS that shipped before those instruction sets existed and never enables `CR4.OSFXSR` on its own. The driver sets `CR4.OSFXSR`, installs a `#NM` (vector 7) handler that gives every thread its own `XMM`/`MXCSR` state, and detours `SwapContext` so that state survives context switches. The result: NT 4-era software that assumes SSE — including Sun's **Java 6**, whose HotSpot JIT emits SSE/SSE2 — runs on 3.51.

Confirmed on real NT 3.51 hardware: `ssetest.exe` reports SSE and SSE2 working, and a four-thread concurrency test shows per-thread XMM state preserved across context switches. With the driver unloaded, SSE instructions raise `#UD` (illegal instruction) — which is exactly the fault Java 6 hits without it.

> **Do not build or run this on a machine you care about.** This is a 1990s-era kernel driver that patches the interrupt descriptor table and rewrites kernel code. It works, but a bug can hard-hang the OS. The installer stays at `Start=3` (demand start) on purpose so a failed load cannot stop the machine booting.

---

## Repo contents

| Path | What it is |
|---|---|
| `nt351sse.c` | the SSE driver (source) |
| `nt351sse.reg` | service registry values (reference; enter by hand on 3.51) |
| `BUILDSSE.BAT` | builds `nt351sse.sys` (NT 4.0 DDK + MSVC 4.2, then restamps to 3.51) |
| `ssetest.c` | user-mode acceptance test — does SSE execute, and is XMM per-thread? |
| `BUILDTEST.BAT` | builds `ssetest.exe` |
| `ntver.c` / `ntver.reg` / `BUILD.BAT` | minimal test driver that first proved the toolchain produces 3.51-loadable binaries |
| `stamp351.py` | rewrites a PE image's version stamps to NT 3.51 and fixes the checksum |
| `checkimports.py` | verifies a binary's imports all exist in a given kernel/hal |
| `findidt.py` | recovers the IDT from a kernel image and prints trap handlers by vector |
| `nmsig.py` | confirms the `#NM` signature match that makes the handler hook valid |
| `FindSwap.java` / `Decomp.java` | Ghidra headless scripts that located 3.51's `SwapContext` |

Everything below this point is the full working log: build notes, the install procedure, the reverse-engineering that located `SwapContext` at `0x8013cd90`, and the increment-by-increment record including a hang this code caused and the fix. It is deliberately detailed.

---

## Building from source

### What you need

Three things, none of which can be linked here:

* **Microsoft Visual C++ 4.2** (`CL.EXE`, `LINK.EXE`).
* **The Windows NT 4.0 DDK** (headers in `DDK\INC`, import libs in
  `DDK\LIB\I386\FREE`).
* A reference copy of **`ntoskrnl.exe` from NT 3.51** — used by `stamp351.py`
  to read the version fields and by `checkimports.py` to prove the driver's
  imports all exist in the real 3.51 kernel. The matching `hal.dll` is optional;
  it just silences the (false-positive) `Kf*` warnings described below.

These are 32-bit tools, but they run fine on a modern 64-bit Windows host.
Build on the modern machine and copy the output onto the 3.51 box — do not try
to build on NT 3.51 itself. 

### Layout the batch files expect

`BUILDSSE.BAT` and `BUILDTEST.BAT` resolve the toolchain relative to this
repo folder. Put everything in one parent directory:

```
<root>\
  nt351sse\            <- this repository
  MSVC420\             <- Visual C++ 4.2
  WinNT4ddk.English\DDK\  <- NT 4.0 DDK (INC + LIB\I386\FREE)
  winnt351_ntoskrnl\   <- ntoskrnl.exe (and optionally hal.dll) from 3.51
```

If your layout differs, edit the three `set` lines at the top of
`BUILDSSE.BAT` (`MSVC`, `DDK`, `NT351`).

### Steps

1. **Build the driver** — run `BUILDSSE.BAT`. It compiles `nt351sse.c` with
   `CL.EXE`, links with `LINK.EXE` against the DDK's `ntoskrnl.lib`/`hal.lib`,
   then runs `stamp351.py` to rewrite the PE version stamps to 3.51 (the NT 4.0
   DDK hardcodes 4.00) and finally runs `checkimports.py` against the 3.51
   kernel. Output: **`nt351sse.sys`**.

2. **Build the test** — run `BUILDTEST.BAT`. It compiles `ssetest.c` with
   `CL.EXE`, links a console app against the static single-threaded CRT (so its
   only DLL dependency is `KERNEL32.dll`), and stamps it to 3.51. Output:
   **`ssetest.exe`**.

Both scripts print a PASS/FAIL verdict. A note on the warnings: if
`checkimports.py` says `KfAcquireSpinLock` / `KfReleaseSpinLock` /
`KfRaiseIrql` / `KfLowerIrql` are "missing", that is a **false positive** —
those are `hal.dll` imports, and `checkimports.py` was only given the kernel.
NT 3.51's own `ntoskrnl.exe` imports all four from `HAL.dll`, so the real HAL
exports them; pass the HAL to the checker to confirm. (The driver has loaded
and run on hardware, so this is settled.)

---

## Installing the driver on NT 3.51

NT 3.51 ships **only `REGEDT32`**, which has **no import function** for text
`.reg` files — it can only restore a binary hive. So the `.reg` files in this
repo cannot be imported on 3.51; they exist as a reference. Setting the values
by hand is quick and reliable, and it is what is described here.

### 1. Copy the file

Copy `nt351sse.sys` into the drivers directory. On a default 3.51 install that
is `C:\WINNT35\SYSTEM32\DRIVERS\` (check `%SystemRoot%` if yours differs).

### 2. Create the service key and values by hand

Run `REGEDT32`, select the **`HKEY_LOCAL_MACHINE`** window, and navigate to
`SYSTEM\CurrentControlSet\Services`. Then:

* **Edit → Add Key** — name it `nt351sse`, leave Class blank.
* Select the new `nt351sse` key and **Edit → Add Value** six times:

| Name | Type | Value | Meaning |
|---|---|---|---|
| `Type` | `REG_DWORD` | `1` | kernel driver |
| `Start` | `REG_DWORD` | `3` | **DEMAND_START** — load on request |
| `ErrorControl` | `REG_DWORD` | `1` | log errors, keep booting |
| `Group` | `REG_SZ` | `Base` | load group |
| `Tag` | `REG_DWORD` | `1` | order within the group |
| `ImagePath` | `REG_EXPAND_SZ` | `\SystemRoot\system32\drivers\nt351sse.sys` | full path, expandable |

Two details that trip people up:

* `REGEDT32` enters `REG_DWORD` values in **hex** by default. For `1` and `3`
  hex and decimal agree, so it does not matter here.
* `ImagePath` must be **`REG_EXPAND_SZ`**, not plain `REG_SZ`. Use the exact
  fully-qualified value above — `\SystemRoot\system32\drivers\nt351sse.sys` —
  which is the form verified to work.

### 3. Load and verify

From a command prompt:

```
net start nt351sse
ssetest.exe
```

**`The nt351sse service was started successfully.`** means the driver loaded and
`DriverEntry` returned `STATUS_SUCCESS`. Then `ssetest.exe` should report:

* `SSE addps : WORKING` and `SSE2 addpd : WORKING` — SSE executes.
* `per-thread XMM : PRESERVED` — state survives context switches.

On a stock 3.51 box *without* the driver, `ssetest` reports `SSE : FAULTED`
(illegal instruction) — so the flip to `WORKING` is the proof it loaded.

If `net start` fails instead, the error number tells you why: **2 / 3** means the
`ImagePath` is wrong or the file is not in `DRIVERS\`; **31** means `DriverEntry`
ran and refused (check Event Viewer for the reason code); **1058** means `Start`
is `4`; **1060** means the key is missing or in the wrong place.

### 4. Unload / remove

```
net stop nt351sse
```

unloads the driver (it restores the IDT gate, removes the `SwapContext` detour,
and clears `CR4.OSFXSR`). To remove it entirely, delete the `nt351sse` key from
`Services` and the `.sys` file.

**Keep `Start=3`.** This driver rewrites kernel code; demand-start is deliberate
so that if a future version misbehaves, a reboot comes up clean rather than
failing to boot. Only move to `Start=0` (boot start) after it has seen a lot of
uneventful uptime.

---

# nt351test — NT 4.0 DDK driver on Windows NT 3.51

In this folder:

1. **`ntver.sys`** — a driver built with the **NT 4.0 DDK + MSVC 4.2** that loads
   and runs on **NT 3.51**, proving the toolchain target works. It reports CPU
   feature bits (MMX / FXSR / SSE / SSE2) via `DbgPrint` and the event log.
2. **`checkimports.py`** — the tool that decides whether *any* driver can load on
   3.51, by resolving its import table against the real `ntoskrnl.exe` /
   `hal.dll` export tables you supplied.
3. **`findidt.py`** — recovers the IDT from a kernel image and prints every trap
   handler *by vector number*. This is what located 3.51's `#NM` handler.
4. **`nmsig.py`** — answers one question: does `intlfxsr.sys`'s `#NM` signature
   check pass against a given kernel? On your 3.51 kernel: **yes, unmodified**.

Plus the feasibility analysis for the actual goal — porting `intlfxsr.sys`
(NT 4 `nt4sse`) to NT 3.51 — at the bottom.

---

## Build

```
BUILD.BAT
```

**Verified: this builds and passes the import check.** `ntver.sys` (2400 bytes)
was produced with MSVC 4.2 + the NT 4.0 DDK, restamped to 3.51, and all 10 of
its imports resolve against the supplied NT 3.51 `ntoskrnl.exe` (858 exports).

Requires Python 2.6+ or 3.x (the machine has 3.4.3 at `C:\Python34\python.exe`;
`BUILD.BAT` calls plain `python`, so adjust if that name is not on `PATH`).

### Three things that will bite you

1. **`/Gz` is mandatory.** In `ntddk.h` most `NTKERNELAPI` functions carry no
   explicit calling convention — they inherit it from the compiler's default.
   Without `/Gz` you get `LNK2001: unresolved external symbol
   __imp__ExAllocatePoolWithTag` because the library exports the stdcall-mangled
   `__imp__ExAllocatePoolWithTag@12`. The `Zw*` functions are declared `NTAPI`
   (explicit `__stdcall`), which is why only the non-`Zw` ones break — a
   confusing partial failure. `BUILD.BAT` sets `/Gz`.
2. **`-nodefaultlib` is mandatory.** Otherwise the linker tries to pull in
   `LIBC.LIB` (`LNK1104: cannot open file "LIBC.lib"`). The DDK's own makefile
   does this too (`MAKEFILE.DEF:1305`). A kernel driver must not link the CRT —
   check with `dumpbin /symbols ntver.obj | grep UNDEF`; you should see only
   `DbgPrint`, `KeNumberProcessors`, and `__imp__` kernel thunks.
3. **Git Bash mangles `/flag` into a path.** Running `cl /c file.c` under MSYS
   yields `Command line warning D4024 : unrecognized source file type
   'C:/Program Files/Git/nologo'`. Use `MSYS_NO_PATHCONV=1
   MSYS2_ARG_CONV_EXCL='*'`, or use dash-form flags (`-nologo -c`) as
   `BUILD.BAT` does. This bites `cmd.exe` users not at all — it is purely an
   MSYS artifact.

### Why `stamp351.py` exists

`DDK\INC\MAKEFILE.DEF` line 1300 hardcodes:

```
LINK_OS_VERSIONS = -version:4.00 -osversion:4.00
```

`SUBSYSTEM_VERSION` in `SOURCES` only feeds `-subsystem:native,<ver>`. The
`-version:` / `-osversion:` pair is not overridable, so every DDK binary claims
to require NT 4.0. `stamp351.py` rewrites `MajorOperatingSystemVersion`,
`MajorImageVersion` and `MajorSubsystemVersion` to 3.51 and recomputes the PE
checksum.

For a *driver* this is probably not strictly necessary — `MmLoadSystemImage`
does not apply the user-mode `-subsystem` version gate. It is cheap insurance,
and if the load does fail, having the stamps correct removes one variable.

### Build settings that matter

| Setting | Value | Why |
|---|---|---|
| `-subsystem:native` | — | no subsystem; `MAKEFILE.DEF:2282` uses this for `TARGETTYPE=DRIVER` |
| `-driver` | — | kernel-mode image (`MAKEFILE.DEF:1384`) |
| `-align:0x20` | — | `DRIVER_ALIGNMENT` default (`MAKEFILE.DEF:~1330`) |
| `-base:0x10000` | — | `DRIVERBASE` (`MAKEFILE.DEF:791`) |
| `-entry:DriverEntry` | — | `MAKEFILE.DEF:2284` |
| `/Gz` | stdcall | DDK calling convention |
| `/Zp8` | 8-byte packing | matches DDK struct layout |

---

## Install and test on NT 3.51

Two stages on purpose. **Stage 1 uses `Start=3` (DEMAND_START)** so the driver
can be loaded and unloaded from a running system with no reboot: you get the
pass/fail answer in seconds, and a failure cannot affect the next boot. Only
once that passes is there any reason to move to `Start=0`.

### Stage 1 — load on demand

Copy `ntver.sys` to `C:\WINNT35\SYSTEM32\DRIVERS\` (adjust if your system
root differs — check `%SystemRoot%`).

**NT 3.51 ships only `REGEDT32`**, which cannot import a `REGEDIT4` text file — it
can only restore a binary hive. So `ntver.reg` is **not** importable on 3.51; it
is there for inspection on a modern machine. Set the values by hand:

Run `REGEDT32`, select the `HKEY_LOCAL_MACHINE` window, and navigate to
`SYSTEM\CurrentControlSet\Services`. Then **Edit → Add Key**, name `ntver`,
leave Class blank. Select the new `ntver` key and **Edit → Add Value** six times:

| Name | Type | Value | Meaning |
|---|---|---|---|
| `Type` | `REG_DWORD` | `1` | kernel driver |
| `Start` | `REG_DWORD` | `1` | running the driver at system startup |
| `ErrorControl` | `REG_DWORD` | `1` | normal error handling |
| `Group` | `REG_SZ` | `Base` | load group |
| `Tag` | `REG_DWORD` | `1` | order within the group |
| `ImagePath` | `REG_EXPAND_SZ` | `\SystemRoot\system32\drivers\ntver.sys` | full path, expandable |

You can also change the Start flag from 1 to 3 if you want to start the driver manually after the OS starts (why?)

`REG_DWORD` values are entered in **hex** by default in `REGEDT32` — for these
values hex and decimal agree, so it does not matter here.

Then load it, from a command prompt (start flag 3):

```
net start ntver
```

**`The ntver service was started successfully.` is the test passing.** That
message means the loader mapped an NT 4.0 DDK binary, resolved all 10 imports
against the 3.51 kernel, called `DriverEntry`, and got `STATUS_SUCCESS` back.
Nothing else needs to be true for the toolchain question to be answered.

**This has now been run on real NT 3.51 hardware and passed.** `net start ntver` returned *"The ntver service was started successfully."* An NT 4.0 DDK + MSVC 4.2 binary, restamped to 3.51 with `stamp351.py`, loaded and ran; all 10 ntoskrnl imports resolved and `DriverEntry` returned `STATUS_SUCCESS`. The toolchain question is settled: **the NT 4.0 DDK toolchain produces binaries that run on NT 3.51.**

Two things observed on the live machine worth recording:

* **`ImagePath` is the fully-qualified form `\SystemRoot\system32\drivers\ntver.sys`.** That spelling was verified to work in `REGEDT32`; use it (rather than the `%SystemRoot%`-relative `System32\DRIVERS\ntver.sys`). The value type must be `REG_EXPAND_SZ`.
* **The driver's own event-log entry shows CPUID leaf 1 EDX = `0x078BFBFF`** in Event Viewer's Data pane (`ff fb 8b 07`, little-endian; it appears twice, as `UniqueErrorValue` and `DumpData[0]`). Decoded: bit 23 (MMX), bit 24 (FXSR), bit 25 (SSE), **and** bit 26 (SSE2) are all set. `intlfxsr.sys` gates on bits 24 **and** 25, so that machine passes the SSE driver's CPUID check with room to spare. Event Viewer renders the entry as type *Error* despite `FinalStatus = STATUS_SUCCESS` — cosmetic, an artifact of logging under an `ErrorCode` field with no registered message DLL (the *"description for Event ID 0 ... could not be found"* text is expected and is not a failure).

Control Panel → **Devices** is the GUI equivalent: find `ntver`, press
**Start**. To unload: `net stop ntver` (the driver sets `DriverUnload`, so this
works and is clean).

### What the failure messages mean

`net start` reports `A system error has occurred. System error N`. Two of these
are real answers about compatibility; the rest are setup slips.

| Error | Meaning | What it tells you |
|---|---|---|
| **127** | The specified procedure could not be found | **Real incompatibility.** `STATUS_PROCEDURE_NOT_FOUND` — an import is absent from 3.51's kernel. This is exactly what `checkimports.py` predicts, and it reports none for this driver. |
| **193** | Is not a valid Windows NT application | **Real incompatibility.** The PE image was rejected outright — format or version gate. |
| 2 / 3 | Cannot find the file / path | `ImagePath` wrong, or the `.sys` is not in `DRIVERS\`. Use the fully-qualified `\SystemRoot\system32\drivers\...` form and make sure the value type is `REG_EXPAND_SZ`. |
| 31 | A device attached to the system is not functioning | `DriverEntry` ran and returned a failure status. The driver loaded — this is a code problem, not a compatibility one. |
| 1058 | The service is disabled | `Start` is `4`. |
| 1060 | The specified service does not exist | Key name or location wrong; it must be directly under `Services`. |

### Confirming what it found

The load succeeding is the whole test. To see the CPU feature bits it read:

* **Event Viewer** (no debugger needed): **Log → System**, look for source
  `ntver`. Open the entry — the **Data** pane shows one DWORD, the CPUID leaf 1
  EDX value. Read the bits: **23 = MMX, 24 = FXSR, 25 = SSE, 26 = SSE2**. So
  e.g. `0x0383FBFF` has all four set.

  Event Viewer will also say *"The description for Event ID ( 0 ) in Source
  ( ntver ) could not be found."* **That is expected and is not a failure** —
  the driver registers no message DLL, so there is no text to look up. The
  entry's existence and its data are the payload.

* **Kernel debugger attached:** the `DbgPrint` output is more direct —

  ```
  ntver: DriverEntry, built with NT 4.0 DDK / MSVC 4.2
  ntver: KeNumberProcessors = 1
  ntver: CPUID.1 EAX=00000f29 EDX=bfebfbff
  ntver:   MMX  yes
  ntver:   FXSR yes
  ntver:   SSE  yes
  ntver:   SSE2 yes
  ntver: Session Manager read status=c0000034 ForceNpxEmulation=0
  ntver: load complete
  ```

  `status=c0000034` is `STATUS_OBJECT_NAME_NOT_FOUND` and is the **expected**
  result — `ForceNpxEmulation` normally does not exist. It proves the `Zw*`
  registry path works from kernel mode, which is what that call is there to
  test. A value of `00000000` means the value existed and was read.

### Stage 2 — boot start

Only after stage 1 passes. Change `Start` to `0` (BOOT_START) and reboot.

`Start=0` is what a working SSE driver needs, because the `CR4` and
context-switch patches must be in place before any user-mode thread can execute
an SSE instruction. For `ntver.sys` it changes nothing functionally — it is
purely a rehearsal of the load path the real driver will use.

`ErrorControl=1` means a boot-start failure is logged and boot continues, so
this is recoverable. If a future driver ever does hang the boot, use **Last
Known Good** (press the spacebar when prompted during startup).

To disable either way: set `Start` to `4` and reboot, or delete the key.

---

## What the driver actually does

`DriverEntry` only. No device object, no dispatch table, no IRPs.

* `KeNumberProcessors` — read via `*KeNumberProcessors`; the 4.0 DDK declares
  it `extern PCCHAR KeNumberProcessors` (`NTDDK.H:75`), so it is a pointer to
  the count, not the count.
* CPUID probe — MSVC 4.2 has no `__cpuid` intrinsic and its inline assembler
  cannot encode `0F A2`, so the instruction is emitted as raw bytes via `_emit`.
  The EFLAGS.ID toggle test runs first to confirm CPUID exists at all.
* Session Manager registry read — `ZwOpenKey` / `ZwQueryValueKey` against
  `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager`,
  reading `ForceNpxEmulation`. This exercises the same kernel registry path the
  SSE driver uses.
* Event log write — `IoAllocateErrorLogEntry` / `IoWriteErrorLogEntry`.

Every one of those imports was verified present in your `ntoskrnl.exe` before
the code was written. `RtlZeroMemory` is deliberately **not** used: in this DDK
it is a macro for `memset` (`NTDDK.H:1606`), which would pull in the CRT and
add imports that have nothing to do with the test.

---

## `checkimports.py` — the load-blocker check

```
python checkimports.py <driver.sys> <ntoskrnl.exe> [hal.dll ...]
```

The NT loader resolves every import **by name** at load time. One missing name
= `STATUS_PROCEDURE_NOT_FOUND` (`0xC000007A`), and `DriverEntry` never runs.
This resolves a driver's import table against the reference kernel's real
export table, so you get the answer before touching a VM.

Run against the shipped `intlfxsr.sys` and your NT 3.51 kernel, it reports the
six missing symbols you already identified, plus everything that *does*
resolve — which is the information that matters for the port.

---

## `findidt.py` / `nmsig.py` — reading the trap table

```
python findidt.py <ntoskrnl.exe> [vector ...]        # default: vectors 7 and 19
python nmsig.py <intlfxsr.sys> <ntoskrnl.exe>
```

`findidt.py` recovers the IDT out of the kernel image, so handlers come out
indexed **by vector number** instead of by pattern-matching guesswork. Two
approaches that look obvious both fail first, and it is worth knowing why:

1. **Scanning for `push 0 / push <vector> / jmp common` finds nothing.** NT has
   no per-vector stubs. The entire trap-frame setup (`ENTER_TRAP`) is *inlined*
   at the top of every handler — which is exactly why the prologue is 54 bytes
   of pushes and segment loads rather than a 7-byte thunk.
2. **Scanning for i386 gate descriptors also finds nothing.** MASM cannot emit a
   split flat offset at assembly time, so the kernel ships the table
   **unswizzled** — `dd offset handler / dw 8E00h / dw 8` — and `KiInitializeIdt`
   shuffles the halves into real gates at boot. `findidt.py` decodes that form
   (and real gates too, for memory dumps).

On your kernel it reports the template in `INIT` at VA `801afd2c`, 256 vectors.
Cross-checks that confirm the index↔vector mapping is right: vectors 3 (`#BP`)
and 4 (`#OF`) come out DPL3 as they must be; `0x2A`-`0x2E` are the DPL3 service
vectors with `KiSystemService` at `80138ab0`; and `0x30`-`0xFF` are a uniform
array of 10-byte `KiUnexpectedInterrupt` stubs from `801381d0`.

`nmsig.py` then replays the driver's own check — extract both blobs, pull the
live vector 7 handler, `RtlCompareMemory`, report which blob wins and what the
resume address would be. It also lists any relocations inside the compared
range, because a reloc there would mean the on-disk bytes differ from the loaded
ones and the comparison would be meaningless. There are none.

(`findtrap.py`, the earlier tool built on model 1 above, has been removed. Its
premise was wrong, not its code.)

---

## Feasibility: SSE on NT 3.51

**It is possible. It is a rewrite of the hooking layer, not a port.**

### How `intlfxsr.sys` works (from the decompilation)

1. `FUN_00010cbd` reads `ForceNpxEmulation` from the Session Manager key. If the
   value exists, is 4 bytes, and is neither 0 nor 1 → returns 1 → `DriverEntry`
   bails with error 2.
2. Per processor: `KeSetAffinityThread` to that CPU, then `FUN_000102a0`:
   EFLAGS.ID toggle, CPUID leaf 0 vendor compare against `"GenuineIntel"`, then
   leaf 1 EDX. Requires **bit 24 (FXSR) AND bit 25 (SSE)** — the check
   `(EDX & 0x1000000) == 0 || (EDX & 0x2000000) == 0` fails if either is absent.
   EDX is stashed in `DAT_000106c0/c4/c8`.
3. `ExAllocatePoolWithTag(NonPagedPool, 0x228, 'FXSR')` per CPU — a
   `KPRCB`-shaped block, every field offset `+0x204` holding the real
   allocation pointer for freeing.
4. 32 × `ExAllocatePoolWithTag(0, 0x84, 'FXSR')` pushed onto an **SLIST** — the
   per-thread x87/SSE save-area pool.
5. `PsSetLegoNotifyRoutine(NULL)` — returns the *previous* value (an old
   single-callback registration API). This is the thread-*teardown* hook.
6. `InterruptDescriptorTableRegister()` → IDT entry **+0x38** = **vector 7** =
   `#NM` (device-not-available). The two byte ranges in the image
   (`0x1034b`-`0x10381`, `0x10314`-`0x10349`) are **not inert signature data —
   they are the driver's two replacement `#NM` handlers.** Each opens with a
   verbatim copy of the kernel handler's 54-byte `ENTER_TRAP` prologue, so the
   `RtlCompareMemory` both validates the kernel build *and* selects which blob to
   install: on a match the driver stores that blob's address (later written into
   IDT[7]) and sets its resume address to `live_handler + len`, i.e. just past
   the prologue it duplicated. Two blobs exist because two NT 4.0 builds differ
   by one instruction there — `push -1` vs `sub esp,4`.
7. `PsSetCreateThreadNotifyRoutine(&LAB_00010780)` — thread *creation* hook.
8. `KeSetSwapContextNotifyRoutine()` + `MmLockPagableDataSection(...)` — the
   context-switch hook, pinned so it cannot be paged out.
9. Per-CPU `KeInitializeDpc` / `KeSetImportanceDpc(2)` /
   `KeSetTargetProcessorDpc` / `KeInsertQueueDpc` — repoints IDT vector 7 to the
   driver's own handler on every processor.
10. `FUN_00010c1c` **hot-patches ntoskrnl text**: checks for the `(%...%)`
    import-thunk pattern, dereferences to the real target, then writes
    `*target = 0xE9` with a relative displacement — a 5-byte `JMP`.

The mechanism is: trap `#NM`, enable `CR4.OSFXSR`/`OSXMMEXCPT`, and extend the
kernel's per-thread FPU context to cover XMM state.

### What NT 3.51 is missing, and what to do about each

| Missing in 3.51 | Used for | Replacement |
|---|---|---|
| `ExInterlockedPopEntrySList`<br>`ExInterlockedPushEntrySList` | SLIST save-area pool | **Available workaround.** 3.51 has no `SLIST_HEADER` at all (it arrived in NT 4.0) and no `Ex*Interlocked*EntrySList`. But it *does* export `ExInterlockedPopEntryList` / `PushEntryList` / `RemoveHeadList` / `InsertHeadList` / `InsertTailList`, operating on `SINGLE_LIST_ENTRY` + `KSPIN_LOCK`. Rewrite the pool on those. |
| `KeSetAffinityThread` | pin thread to each CPU | **Drop it.** 3.51 has no per-processor DPC targeting or thread affinity. Just process the boot CPU. Fine for the uniprocessor machines 3.51 actually ran on. |
| `KeSetSwapContextNotifyRoutine` | hook context switch | **The one that needed reverse-engineering — now located.** 3.51's `SwapContext` is at **`0x8013cd90`** (235 bytes; see `FindSwap.java`). No notify call site exists in it, so replicate the nt4sse mechanism by inline-patching it with the driver's own `FUN_00010c1c` `JMP`-detour trick. Patch site and register contract confirmed below. |
| `PsSetCreateThreadNotifyRoutine` | hook thread create | **No equivalent in 3.51.** 3.51 has only `PsSetCreateProcessNotifyRoutine`. Patch the thread-object creation path. |
| `PsSetLegoNotifyRoutine` | hook thread teardown | **No equivalent.** Patch the thread-object delete path, or hook the object type's `DeleteProcedure`. |

Additional things the port has to deal with:

* **The `#NM` signature check already passes on 3.51 — this blocker is gone.**
  It was reasonable to expect the hardcoded NT 4.0 prologue not to match. It
  does. 3.51's vector 7 handler is at **`8013a930`** (file offset `0003a930`),
  and its first **54 bytes are byte-identical to variant A** (`0x1034b`-`0x10381`),
  `sub esp,4` form included — the `ENTER_TRAP` prologue did not change between
  3.51 and 4.0. Supporting checks: no relocations fall inside the compared range,
  so the on-disk bytes are exactly what `RtlCompareMemory` sees; the 54 bytes
  decode to exactly 22 whole instructions; and the resulting resume address
  `8013a966` lands on an instruction boundary (`mov ebp,esp`), not mid-opcode.
  Variant B diverges at +31, precisely where the two NT 4.0 builds differ, so the
  match is discriminating rather than accidental. Reproduce with `nmsig.py`.
  One caveat: this compares the **on-disk image**. Re-check against the live IDT
  on the target machine, since a boot-time patch to the handler would not show
  up here.
* **`KfRaiseIrql` / `KfLowerIrql` are not a problem.** These two are the one
  pair `checkimports.py` reports as missing, but they are **hal.dll** imports,
  not ntoskrnl ones — and `hal.dll` was not supplied. They are safe: the NT 3.51
  `ntoskrnl.exe` itself imports both from `hal.dll` (along with
  `KfAcquireSpinLock` / `KfReleaseSpinLock`), so 3.51's HAL must export them.
  Re-run with the real `hal.dll` to confirm:
  `python checkimports.py intlfxsr.sys <ntoskrnl.exe> <hal.dll>`
* **`PsSetLegoNotifyRoutine` is a single-callback API** — note the old value is
  saved into `DAT_00010764` and later indexed by thread pointer
  (`*(int*)(DAT_00010764 + thread)`), i.e. an array indexed by *thread ID*. That
  indexing scheme has to be re-derived for 3.51's thread-ID space.
* **Unmasked SIMD exceptions — confirmed absent.** Vector 19 (`#XM`) maps to
  `8013c10c`, the generic catch-all **shared by 16 vectors** (15, 18-31, 47), so
  3.51 has no `#XM` handler at all. Leaving `CR4.OSXMMEXCPT` **clear** is both
  the safe choice and well-defined: with the bit clear, an unmasked SIMD
  exception raises `#UD` instead of `#XM`. Since MXCSR masks all six SIMD
  exceptions at reset, ordinary code never reaches that path. Only set
  `OSXMMEXCPT` if you first install a real vector 19 handler.

### `SwapContext` on NT 3.51 — located

This was the last hard blocker: `SwapContext` is not exported and not reachable from the IDT, so it had to be found by structure. It is at **`0x8013cd90`** in this 3.51 kernel (`.text`, file offset `0x03cd90`, 235 bytes). Reproduce with `FindSwap.java` (a Ghidra headless post-script that flags every function touching `CR0`/`CR3`/`CR4`, `LLDT`/`LTR`, or FPU state) and `Decomp.java` (decompiles it).

Why the identification is certain, not a guess:

* It reloads **`CR3`** (`0f 22 d8` at `8013ce12`, address-space switch), the **LDT** (`lldt` at `8013ce50`, gated on the outgoing vs incoming `KPROCESS` at `KTHREAD+0x40` differing), **and** toggles **`CR0.TS`** (`0f 22 c1` at `8013cdc2`) — the three only ever happen together in a context switch.
* The decompiler recovers the exact `SwapContext` register contract: `__fastcall` with **ESI = outgoing thread, EDI = incoming thread, EBX = PRCB**, ending by requesting the APC software interrupt (`HalRequestSoftwareInterrupt`) when the incoming thread has one pending.
* Its callers include **`KiDispatchInterrupt`** (`0x8013cd10`) plus the other dispatcher entry points — exactly what calls `SwapContext`.

The CR0 block is the interesting part for the port:

```
8013cdb0  0f 20 c5        mov ebp, cr0
8013cdb3  8b cd           mov ecx, ebp
8013cdb5  83 e1 f1        and ecx, 0xfffffff1     ; clear TS, MP, EM
8013cdb8  0a 4e 2d        or  cl, [esi+0x2d]      ; OR in new thread's NPX flags
8013cdbb  0b 48 6c        or  ecx, [eax+0x6c]     ; OR in PRCB NPX flags
8013cdbe  3b e9           cmp ebp, ecx
8013cdc0  74 03           jz  +3
8013cdc2  0f 22 c1        mov cr0, ecx            ; lazy-FP TS reload
```

This is the native x87 lazy-switch logic. A thread that actively uses x87 keeps `TS` **clear** across switches, so it will *not* `#NM` on the way back in — which is exactly why nt4sse cannot rely on `#NM` alone and needs a per-switch hook: to force SSE state to be saved/tagged on **every** switch, not just the ones where the kernel happens to set `TS`. The cleanest detour is a 5-byte `JMP` at the `0x8013cd90` entry (old/new thread still in ESI/EDI), with a trampoline for the displaced bytes (`0a c9 9c 8b 0b` = `or cl,cl` / `pushf` / `mov ecx,[ebx]`).

### The six missing APIs, re-classified

Working through the decompilation changes the picture from "six missing functions" to "one that mattered":

* **`ExInterlockedPopEntrySList` / `ExInterlockedPushEntrySList`** — a free pool of 132-byte (`0x84`) FXSAVE buffers (`FUN_0001048c` pops, `FUN_00010c75` drains, `DriverEntry` pre-fills 32). *Mechanical swap* to 3.51's `SINGLE_LIST_ENTRY` + `KSPIN_LOCK` list primitives.
* **`KeSetAffinityThread`** — pins the init thread to each CPU for per-CPU CPUID and IDT patching. *Drop on uniprocessor* (what 3.51 overwhelmingly ran on); on MP, the driver already fans the IDT patch out via `KeSetTargetProcessorDpc` DPCs, so reuse that.
* **`PsSetCreateThreadNotifyRoutine`** — pre-allocates a thread's FX buffer at creation (`LAB_00010780`). *An optimization*, not correctness: `FUN_0001048c` already allocates lazily on first `#NM`. Drop it and lean on the pre-filled pool, or hook thread-object creation.
* **`PsSetLegoNotifyRoutine`** — called as `PsSetLegoNotifyRoutine(0)` only to obtain a **free per-`KTHREAD` pointer slot** (`DAT_00010764`) for stashing each thread's FX-buffer pointer, indexed as `*(KTHREAD + DAT_00010764)`. *Replace* with a driver-side thread→buffer table keyed on `KeGetCurrentThread()`, or a hardcoded known-free 3.51 `KTHREAD` offset.
* **`KeSetSwapContextNotifyRoutine`** — the real blocker, and the only one with no API substitute, because 3.51's `SwapContext` has no notify call site. *Resolved above:* inline-patch `SwapContext` at `0x8013cd90`.

So four of the six are non-blockers (two mechanical, one droppable, one a storage-strategy swap), and the fifth is unblocked now that `SwapContext` is located.

### Honest bottom line

The CPU-side work — CPUID gating, `CR4` bits, `FXSAVE`/`FXRSTOR`, extending the
per-thread save area — is all doable on 3.51; none of it depends on NT 4 APIs.
The problem is entirely in the **hooking layer**, where all five notification
APIs are absent. Four of the five have a realistic replacement (pool rewrite,
drop affinity, two byte-patches, object-type hook). The swap-context hook is the
one that needs real reverse-engineering time, because it is the thing that
actually makes SSE state survive a context switch.

Both hard blockers have now been cleared. The `#NM` signature check needs no work at all (the NT 4.0 prologue matches 3.51 byte-for-byte), and `SwapContext` — the one piece that genuinely required reverse-engineering — is located at `0x8013cd90` with its patch site and register contract confirmed. What is left is engineering, not discovery: rewrite the pool on 3.51 list primitives, pick a per-thread storage slot, drop or re-home the affinity and thread-notify calls, and install the `SwapContext` detour — then rebuild and test each step on hardware, as the toolchain step already was.

The payoff you described is real, though: get this working and NT 4-era
binaries that assume SSE become runnable on 3.51.

### Suggested order of work

1. `BUILD.BAT`, confirm `ntver.sys` loads on 3.51. That validates the toolchain
   and the registry install path — and it is the step that tells you whether
   anything after it is worth doing.
2. ~~Locate the `#NM` handler and extract its prologue bytes.~~ **Done** (no Ghidra needed: vector 7 is `8013a930`, and the driver's variant A blob already matches it byte for byte). ~~Locate `SwapContext`.~~ **Done** — `0x8013cd90`, via `FindSwap.java` / `Decomp.java`; patch site and register contract are documented above.
3. Re-target the hooks, one at a time, rebuilding and testing on hardware after each — the same `Start=3` / `net start` loop that validated `ntver.sys`. Order, easiest first: (a) pool rewrite onto 3.51 list primitives; (b) drop `KeSetAffinityThread` (uniprocessor); (c) replace the `PsSetLegoNotifyRoutine` per-thread slot with a driver-side table; (d) drop or re-home `PsSetCreateThreadNotifyRoutine`; (e) last and most delicate, the `SwapContext` detour at `0x8013cd90`. Keep `CR4.OSXMMEXCPT` clear throughout (no `#XM` handler on 3.51).

## The port: `nt351sse.sys`

The port is built as a **new** driver (`nt351sse.c`), not a binary patch of `intlfxsr.sys`, reusing the `ntver.sys` skeleton that is already proven to load on 3.51. Build it with `BUILDSSE.BAT` (a copy of `BUILD.BAT` retargeted to `nt351sse.c`); install exactly like `ntver` but with the service name `nt351sse` (`nt351sse.reg` mirrors `ntver.reg`).

It is being brought up in increments, each one buildable, loadable, and testable on hardware before the next is written — the same `Start=3` / `net start` loop that validated the toolchain.

### Increment 1 — the 3.51-native data layer (confirmed on hardware)

This increment stands up everything the SSE machinery needs to *store* state, with **none of the six blocker APIs** and **no CPU-state changes or hooks** — so it is completely safe to load and unload. It:

* gates on CPUID `FXSR` + `SSE` (bits 24/25) and honours `ForceNpxEmulation`, like the original;
* builds the per-thread save-area **pool** on 3.51's `SINGLE_LIST_ENTRY` + `KSPIN_LOCK` primitives (`ExInterlockedPushEntryList` / `ExInterlockedPopEntryList`), replacing the NT 4.0 `SLIST`;
* builds the **thread→buffer table** as a spinlock-guarded linear-probe array keyed on `KeGetCurrentThread()`, replacing the `PsSetLegoNotifyRoutine(0)` free-`KTHREAD`-slot trick (chosen for safety: no dependency on undocumented `KTHREAD` layout);
* self-tests the pool + table end to end at load, and logs CPU features to Event Viewer the same way `ntver.sys` does.

Verified here: compiles under MSVC 4.2, links against the NT 4.0 DDK, stamps to 3.51, and **all 13 ntoskrnl imports resolve** against the 3.51 kernel. The import check also flags `KfAcquireSpinLock` / `KfReleaseSpinLock` as missing — a **false positive**, the same one noted for `KfRaiseIrql`/`KfLowerIrql`: these are `hal.dll` imports (from `KeAcquireSpinLock`/`KeReleaseSpinLock`), and 3.51's own `ntoskrnl.exe` imports all four from `HAL.dll`, so 3.51's HAL exports them. Supply the real `hal.dll` to `checkimports.py` to silence it.

**Confirmed on real NT 3.51 hardware.** `net start nt351sse` ran `DriverEntry` to completion and logged its breadcrumb, with `UniqueErrorValue`/`DumpData[0]` = `0x078BFBFF` (the CPU features) and `FinalStatus = STATUS_SUCCESS`. Since the breadcrumb is the last thing `DriverEntry` does, reaching it proves the whole path ran without bugchecking — the pool built, the spinlocks initialised, and the thread→table self-test (pop / assign / lookup / release under the real locks) all executed. And because an unresolved import means the image never loads at all, the success entry is direct proof that the `Kf*` spinlock imports resolve on the live HAL — i.e. the `checkimports` warning really was a false positive.

### Increment 2 — enable SSE via `CR4.OSFXSR` (confirmed on hardware)

This is the increment that makes SSE actually execute. After the data layer is up, `DriverEntry` raises to `DISPATCH_LEVEL` (to pin the processor), reads `CR4`, sets **`OSFXSR` (bit 9)**, writes it back, and loads `MXCSR` with the all-masked default `0x1f80`. `OSXMMEXCPT` (bit 10) is deliberately left **clear** — 3.51 has no `#XM` handler, and with the bit clear an unmasked SIMD exception would raise `#UD`, which `MXCSR`'s reset masks prevent anyway. The CR4 mov and `LDMXCSR` are emitted as raw opcode bytes (MSVC 4.2 knows neither); the assembled bytes were verified in the image (`0F 20 E0` / `0F 22 E0` / `0F AE 10`). `DriverUnload` clears `OSFXSR` again, restoring stock state.

The load breadcrumb now carries three ULONGs so the flip is visible with no debugger: `DumpData[0]` = CPU features, `[1]` = CR4 **before**, `[2]` = CR4 **after** — the after value should have bit 9 set relative to before. Expect `ssetest.exe` to go from `SSE = FAULTED` to `SSE = WORKING` once this is loaded.

**Scope and safety.** Increment 2 makes SSE *execute*; it does **not** yet save or restore XMM state across context switches. That is safe here only because nothing else on a 3.51 box uses XMM — so while a single SSE thread runs (the `ssetest` case) there is no other XMM state to corrupt. Two concurrent SSE users would leak XMM registers between threads. It also enables `OSFXSR` on the **boot CPU only**; on a multiprocessor machine the other CPUs would still `#UD` on SSE (a warning is logged). Both are addressed by the remaining increments.

**Confirmed on real NT 3.51 hardware — SSE executes.** With the driver loaded, `ssetest.exe` reports `MMX = WORKING`, **`SSE = WORKING`**, **`SSE2 = WORKING`**, with the packed arithmetic verified (`addps` → 11/22/33/44, `addpd` → 11/22). That is NT 3.51 running SSE and SSE2 code.

Worth stating why this is attributable to the driver rather than to the OS. `ssetest` runs in user mode and **cannot read `CR4`** (it is ring-0 only), so by itself its output cannot distinguish "the driver enabled SSE" from "SSE was already on". The kernel image settles it: the only routine in 3.51's `ntoskrnl.exe` that writes `CR4` at boot is `FUN_8013d114` (called from `INIT`), and it manipulates **bit 0 (VME) only** —

```
8013d114  0f 20 e0            mov  eax, cr4
8013d117  f7 45 08 01000000   test dword ptr [ebp+8], 1
8013d11e  74 05               jz   +5
8013d120  83 c8 01            or   eax, 1          ; set VME
8013d123  eb 03               jmp  +3
8013d125  83 e0 fe            and  eax, 0xfffffffe ; clear VME
8013d128  0f 22 e0            mov  cr4, eax
```

Nothing in the stock kernel sets bit 9, so `OSFXSR` cannot have been set before the driver ran. (The other CR4 writers, `FUN_8011c62c` / `FUN_8011c6f0`, are the processor-state save/restore pair used around bugchecks, and they only replay a previously saved value.) For a direct in-kernel reading, the driver's own log entry carries CR4 before and after in `DumpData[1]`/`[2]`.

### Increments 3 and 4 — per-thread XMM state (confirmed on hardware)

These are the two that make concurrent SSE *correct* rather than merely possible. Both are installed **before** `OSFXSR` is enabled, and if either refuses to install the driver does not enable SSE at all — enabling it without state tracking is exactly the unsafe configuration increment 2 warned about.

**Increment 3 — the `#NM` (vector 7) handler.** `FXSAVE` saves *both* x87 and XMM state, and the kernel already owns x87, so the handler must not hand the kernel a different x87 image than it expects. Mirroring what `intlfxsr.sys` does, it: clears `CR0.TS` so FP/SSE can run inside the handler; `FXSAVE`s the live state into a per-CPU scratch image; copies **only** `MXCSR` (image `+0x18`) and `XMM0-7` (image `+0xa0`, 128 bytes) out to the previous owning thread's save area; copies the current thread's `MXCSR`/`XMM` in (or clean defaults if it has none yet); `FXRSTOR`s; restores the **original** `CR0` so the kernel still sees `TS` exactly as the trap found it; then jumps into the kernel's own handler at **`+54` bytes**, past the prologue we duplicate. x87 is left entirely to the kernel.

The handler is `__declspec(naked)` (supported by MSVC 4.2) and opens with a hand-written copy of 3.51's 54-byte `ENTER_TRAP` prologue. **Verified: the assembled bytes are byte-identical to the kernel's** — found at `.text+08a0` in the built image, 54/54 matching, with no relocations inside the copied range. The driver re-checks this against the live IDT at load time (comparing the live handler to its own first 54 bytes, so the check is self-referential and needs no separate signature blob) and refuses to hook on a mismatch. Resume address works out to `8013a966`, the same value `nmsig.py` derived independently.

**Increment 4 — the `SwapContext` detour.** A thread actively using x87 keeps `CR0.TS` **clear** across switches, so it never takes a `#NM` on the way back in — meaning the `#NM` hook alone would never notice the switch and XMM would leak between threads. The detour closes that hole: a 5-byte `JMP` over the first 5 bytes of `SwapContext` (`0a c9 9c 8b 0b` = `or cl,cl` / `pushf` / `mov ecx,[ebx]` — three whole instructions, so the split is on an instruction boundary), with a heap trampoline holding the displaced bytes plus a `JMP` back to `SwapContext+5`. It flushes the live XMM out to its owner, marks the CPU unowned, and preserves every register and flag (`pushfd`/`pushad`). The next SSE instruction in the incoming thread takes a `#NM` and loads that thread's state. The expected 5 bytes are verified before patching; on a mismatch it refuses and backs the `#NM` hook out.

**A hang this caused, and the rule that prevents it.** The first build of these increments **froze NT 3.51 solid on load — no BSOD, just a dead machine.** The cause: this file is compiled with `/Gz`, so every C function is `__stdcall` and pops its own arguments (`ret 4`). The hand-written trap-path assembly pushed an argument, called the helper, and *also* did `add esp,4` — double-popping. ESP ended 4 bytes high, the trap frame was corrupted, and the kernel handler's closing `iret` returned to garbage. Because a trap gate runs with interrupts disabled, that presents as a silent hard freeze rather than a bugcheck, which is why there was no crash screen.

The fix was not merely to delete the `add`: `TrapLookupSaveArea` now takes **no arguments** and reads `KeGetCurrentThread()` itself, so there is no argument push and nothing to mis-pop. (3.51's `KeGetCurrentThread` is just `mov eax,[0xffdff124]; ret`, a flat KPCR read, and the optimiser inlines it — so the trap path now makes **zero external calls**, which also removes any chance of calling something that raises IRQL.) Both naked routines are now audited for stack balance in the built image: every path nets **ESP delta 0**. When editing this assembly, re-run that audit — mixing hand-written stack manipulation with `/Gz` callees is the single easiest way to hang the machine here.

**Locking.** Vector 7 is an **interrupt gate** (access `0x8E`) on 3.51, so the CPU clears `IF` on entry — the handler runs with interrupts disabled. On a uniprocessor that makes the thread-table walk atomic *without* a spinlock, which matters because a `#NM` can arrive at any IRQL and a spinlock would not protect against it. For the same reason the trap path pops the free list by hand instead of calling `ExInterlockedPopEntryList` (which acquires a spinlock and raises IRQL — wrong inside a trap gate). The `SwapContext` detour does its own `cli`. Both are uniprocessor-correct.

Also fixed here: increment 1 wrote the default `MXCSR` at the *FXSAVE* offset (`+0x18`) of each per-thread area, but that area is in our own layout (XMM at `+0x00`, `MXCSR` at `+0x80`). Harmless while nothing read it; corrected now that the handler does.

`DriverUnload` removes both hooks before freeing anything they touch, then clears `OSFXSR`, restoring entirely stock state. It also reports counters: `#NM` traps serviced and swap-time flushes.

Still not present: multiprocessor fan-out — `OSFXSR`, the scratch image and the hooks are boot-CPU only (a warning is logged on an MP machine). `CR4.OSXMMEXCPT` stays clear throughout.

**Confirmed on real NT 3.51 hardware, end to end.** With the full driver loaded, `ssetest.exe` reports SSE `WORKING`, SSE2 `WORKING`, and — the part that needs increments 3 and 4, not just `OSFXSR` — **`per-thread XMM : PRESERVED`** under the four-thread, spin-heavy concurrency test.

Why that result is real evidence rather than a lucky pass: the threads spin for tens of millions of iterations and get preempted many times while holding distinct values in `XMM0-7`, so the `#NM` handler and the `SwapContext` detour are both exercised constantly. The `SwapContext` detour also sits on the kernel's single hottest path — it runs on **every** context switch on the boot CPU — so the fact that the system stayed up under that load is itself strong evidence the detour is not corrupting the switch path. (The one thing a single run does not prove is exhaustiveness across every edge case; treat this as working, and keep an eye on long-running stress.)

### What this means, and what is left

The original goal is met on a uniprocessor 3.51 box: SSE, SSE2 and MMX execute, and XMM state is preserved across context switches, so concurrent SSE programs are safe. That is the payoff described at the top of this file — NT 4-era software that assumes SSE should now run on 3.51 (modulo the usual API-shim work that any NT 4 binary needs on 3.51 anyway).

Remaining, in rough priority order:

* **Multiprocessor.** `OSFXSR`, the scratch image and the hooks are boot-CPU only. On an MP box the other CPUs would still `#UD` on SSE (a warning is logged). Needs per-CPU scratch images, a per-CPU free list, and DPC-based fan-out of the `#NM` gate and `SwapContext` detour.
* **Long-run stability.** One clean pass plus clean unload/reload is not the same as days of mixed SSE/x87 load. Worth an overnight stress if this becomes something people rely on.
* **Boot-start hardening.** Once confidence is high, `Start=0` is possible, but only after the unload path and the hook-install guards have seen a lot of cycles — a bug at boot time would stop the machine coming up.
* **Optional hardening.** The detour is non-pageable (NonPagedPool trampoline, and the handler lives in a non-paged section), but a production port would want to pin the code and audit IRQL assumptions formally.

## Acceptance test: `ssetest.exe`

`ssetest.c` is a user-mode console program that answers the only question that ultimately matters: **does SSE actually execute?** It is the before/after gauge for the whole project, and the thing that should flip from FAIL to PASS when the driver's SSE-enable increment lands.

Build it with `BUILDTEST.BAT` (MSVC 4.2, static single-threaded CRT so its only DLL import is `KERNEL32.dll`; restamped to 3.51 like everything else). It:

* prints the CPU vendor and `CPUID.1 EDX`;
* reports which of MMX / FXSR / SSE / SSE2 the CPU *claims*;
* then actually **executes** a packed MMX add, a packed SSE add, and a packed SSE2 add — each wrapped in structured exception handling — and checks the arithmetic, so an instruction the OS has not enabled is reported as `FAULTED` instead of killing the program.

Because MSVC 4.2 predates these instruction sets, every SIMD opcode (and `CPUID`) is emitted as raw bytes, the same technique the driver uses. `MOVUPS`/`MOVUPD` are used so no 16-byte stack alignment is needed.

What to expect:

* **Stock NT 3.51, no driver:** `MMX = WORKING`, `SSE = FAULTED`, `SSE2 = FAULTED`. The fault is `#UD` — the CPU supports SSE but the OS has never set `CR4.OSFXSR`. MMX works because it aliases the x87 stack the kernel already saves and needs no `OSFXSR`. **This is the baseline — capture it first.**
* **After the SSE-enable increment:** `SSE` (and `SSE2`, if the CPU has it) should flip to `WORKING`.

Exit code is scriptable: `0` if SSE works, `2` if SSE faulted, `1` for other states.

Verified on a modern Windows host (where SSE is always enabled) that all three report `WORKING` with correct results — which confirms the hand-encoded opcodes and the CPUID/SEH plumbing are right. The meaningful run is on 3.51.

### The concurrency test

Enabling `OSFXSR` makes SSE *execute*; it does not make it *correct* when more than one thread uses SSE. So `ssetest` also runs a concurrency check: four threads each load a distinct pattern into `XMM0-7`, spin long enough to be preempted many times, then verify every lane still holds their own value. This is the test that distinguishes increment 2 alone from increments 3 + 4.

* `per-thread XMM : PRESERVED` — state survives context switches; concurrent SSE is safe.
* `per-thread XMM : CORRUPTED (n of 4 threads)` — SSE runs but threads clobber each other. Expected with `OSFXSR` set and no per-thread save/restore.

Exit codes: `0` = SSE works and XMM is preserved, `3` = SSE works but concurrency is unsafe, `2` = SSE faulted, `1` = other.

**A pitfall worth recording, because it produced a false failure.** The first version of this test called `Sleep(0)` between loading XMM and checking it, and reported `CORRUPTED (4 of 4)` **on Windows 10** — a system that certainly does preserve per-thread XMM. The cause was the test, not the OS: modern CRT and `KERNEL32` routines use SSE internally, so *any* call out — `Sleep`, `printf` — destroys XMM. Isolated check: `XMM0` reads back as **zero** after a plain `printf`. The fix is that the load, the delay, and the read-back now happen inside **one uninterrupted `_asm` block** with no C or API call in between, yielding via a spin loop rather than politely. It then correctly reports `PRESERVED` on Windows 10. Anyone extending this test should keep that constraint.
