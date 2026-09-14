/*
 * ntver.c - Minimal NT 3.51 compatibility test driver.
 *
 * Purpose: prove that a kernel driver built with the NT 4.0 DDK + MSVC 4.2
 * loads and runs on Windows NT 3.51, and report what the kernel tells us
 * about itself. Everything it calls exists in the NT 3.51 export table.
 *
 * It deliberately uses ONLY APIs verified present in the 3.51 ntoskrnl.exe:
 *   DbgPrint, KeNumberProcessors, RtlInitUnicodeString, ZwOpenKey,
 *   ZwQueryValueKey, ZwClose, ExAllocatePool, ExFreePool,
 *   IoAllocateErrorLogEntry, IoWriteErrorLogEntry.
 *
 * It returns STATUS_SUCCESS so it stays resident, and logs an event so the
 * result is visible in Event Viewer even with no debugger attached.
 */

#include <ntddk.h>

/*
 * CPUID feature probe, written for MSVC 4.2 which has no __cpuid intrinsic
 * and no support for the 0F A2 opcode in its inline assembler. We emit the
 * instruction bytes directly. EDX from leaf 1 carries the feature flags:
 *   bit 23 = MMX, bit 24 = FXSR, bit 25 = SSE, bit 26 = SSE2.
 */
static void
GetCpuFeatures(
    OUT PULONG Edx,
    OUT PULONG Eax
    )
{
    ULONG localEdx = 0;
    ULONG localEax = 0;

    _asm {
        pushad
        mov  eax, 1
        _emit 0x0F
        _emit 0xA2          ; cpuid
        mov  localEdx, edx
        mov  localEax, eax
        popad
    }

    *Edx = localEdx;
    *Eax = localEax;
}

/*
 * Detect CPUID support the classic way: try to toggle EFLAGS.ID (bit 21).
 * If it will not flip, CPUID is not implemented (386/early 486).
 */
static BOOLEAN
HasCpuid(
    VOID
    )
{
    ULONG supported = 0;

    _asm {
        pushfd
        pop  eax
        mov  ecx, eax
        xor  eax, 0x00200000    ; flip ID
        push eax
        popfd
        pushfd
        pop  eax
        xor  eax, ecx
        and  eax, 0x00200000
        mov  supported, eax
        push ecx                ; restore original EFLAGS
        popfd
    }

    return (BOOLEAN)(supported != 0);
}

/*
 * Write a one-off informational entry to the system event log so the result
 * is visible without a kernel debugger. Error code is passed as the
 * ErrorCode field; UniqueErrorValue carries our feature bits, and they are
 * ALSO placed in DumpData so Event Viewer's "Data" pane actually shows them.
 *
 * Without DumpDataSize set, the Data pane renders empty and the log entry
 * proves only "the driver ran" rather than "the driver ran and saw these CPU
 * bits". The packet size must grow to cover the extra ULONG: the packet
 * already contains DumpData[1], so sizeof(IO_ERROR_LOG_PACKET) is enough for
 * one ULONG of dump data with no further padding.
 */
static VOID
LogResult(
    IN PDRIVER_OBJECT DriverObject,
    IN NTSTATUS ErrorCode,
    IN ULONG UniqueValue
    )
{
    PIO_ERROR_LOG_PACKET packet;

    packet = (PIO_ERROR_LOG_PACKET)
        IoAllocateErrorLogEntry(DriverObject,
                                (UCHAR)sizeof(IO_ERROR_LOG_PACKET));

    if (packet != NULL) {
        /*
         * Zero the packet by hand rather than via RtlZeroMemory. On this DDK
         * RtlZeroMemory is a macro for memset, which drags in the C runtime
         * and adds imports for no reason. Keeping the driver free of CRT
         * symbols means the only imports are from ntoskrnl.exe, which makes
         * the NT 3.51 load test meaningful on its own.
         */
        PUCHAR raw = (PUCHAR)packet;
        ULONG  i;

        for (i = 0; i < sizeof(IO_ERROR_LOG_PACKET); i++) {
            raw[i] = 0;
        }

        packet->ErrorCode        = ErrorCode;
        packet->UniqueErrorValue = UniqueValue;
        packet->FinalStatus      = STATUS_SUCCESS;
        packet->DumpDataSize     = (USHORT)sizeof(ULONG);
        packet->DumpData[0]      = UniqueValue;
        IoWriteErrorLogEntry(packet);
    }
}

/*
 * Read HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\ForceNpxEmulation
 * purely to exercise the Zw* registry path from kernel mode on 3.51, which is
 * the same call sequence the SSE driver uses for its opt-out check.
 */
static NTSTATUS
ReadSessionManagerValue(
    OUT PULONG Value
    )
{
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE key = NULL;
    NTSTATUS status;
    ULONG resultLength = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info;
    ULONG infoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG);

    *Value = 0;

    RtlInitUnicodeString(
        &keyName,
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager");

    InitializeObjectAttributes(&attributes,
                               &keyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    status = ZwOpenKey(&key, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(PagedPool, infoSize);
    if (info == NULL) {
        ZwClose(key);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&valueName, L"ForceNpxEmulation");

    status = ZwQueryValueKey(key,
                             &valueName,
                             KeyValuePartialInformation,
                             info,
                             infoSize,
                             &resultLength);

    if (NT_SUCCESS(status) &&
        info->Type == REG_DWORD &&
        info->DataLength == sizeof(ULONG)) {
        *Value = *(PULONG)info->Data;
    }

    ExFreePool(info);
    ZwClose(key);

    return status;
}

/*
 * DriverEntry. Returning STATUS_SUCCESS keeps the driver loaded; there is no
 * device object and no dispatch table because nothing ever sends it an IRP.
 * Unload is provided so the driver can be stopped cleanly.
 */
static VOID
DriverUnload(
    IN PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("ntver: unloading\n");
}

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
{
    ULONG features = 0;
    ULONG version  = 0;
    ULONG npxValue = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("ntver: DriverEntry, built with NT 4.0 DDK / MSVC 4.2\n");
    DbgPrint("ntver: KeNumberProcessors = %d\n", (ULONG)*KeNumberProcessors);

    if (HasCpuid()) {
        GetCpuFeatures(&features, &version);
        DbgPrint("ntver: CPUID.1 EAX=%08lx EDX=%08lx\n", version, features);
        DbgPrint("ntver:   MMX  %s\n", (features & (1 << 23)) ? "yes" : "no");
        DbgPrint("ntver:   FXSR %s\n", (features & (1 << 24)) ? "yes" : "no");
        DbgPrint("ntver:   SSE  %s\n", (features & (1 << 25)) ? "yes" : "no");
        DbgPrint("ntver:   SSE2 %s\n", (features & (1 << 26)) ? "yes" : "no");
    } else {
        DbgPrint("ntver: CPUID not supported by this processor\n");
    }

    status = ReadSessionManagerValue(&npxValue);
    DbgPrint("ntver: Session Manager read status=%08lx ForceNpxEmulation=%lu\n",
             status, npxValue);

    /*
     * Log success with the feature bits as the unique value, so that even on
     * a machine with no debugger the load can be confirmed from Event Viewer.
     */
    LogResult(DriverObject, STATUS_SUCCESS, features);

    DbgPrint("ntver: load complete\n");

    return STATUS_SUCCESS;
}
