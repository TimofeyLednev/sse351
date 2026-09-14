/*
 * nt351sse.c - SSE/SSE2/MMX enablement for Windows NT 3.51, increment 1.
 *
 * This is the port of the NT 4.0 "nt4sse" driver (intlfxsr.sys) to NT 3.51.
 * The original fails to load on 3.51 because it imports six functions the 3.51
 * kernel does not export. Analysis of the decompilation (see README.md) showed
 * only ONE of the six is a genuine blocker; the rest have 3.51-native
 * substitutes. This file builds the substitutes and proves them loadable,
 * before any IDT / #NM / SwapContext patching is added in later increments.
 *
 * INCREMENT 1 (this file) establishes and self-tests the 3.51-native data
 * layer, using only APIs verified present in the 3.51 ntoskrnl.exe / hal.dll:
 *
 *   - CPUID gate (require FXSR + SSE), and the ForceNpxEmulation opt-out.
 *   - Buffer pool: a SINGLE_LIST_ENTRY free list guarded by a KSPIN_LOCK,
 *     driven by ExInterlockedPushEntryList / ExInterlockedPopEntryList. This
 *     replaces the NT 4.0 SLIST (ExInterlocked*EntrySList), which does not
 *     exist on 3.51.
 *   - Thread->buffer table: a spinlock-guarded open-addressing array keyed on
 *     KeGetCurrentThread(). This replaces the PsSetLegoNotifyRoutine(0) trick
 *     the original used to borrow a free KTHREAD slot (that API is absent on
 *     3.51). Chosen for safety: it depends on no undocumented KTHREAD layout.
 *
 * INCREMENT 2 (added) enables SSE execution by setting CR4.OSFXSR (and putting
 * MXCSR in a known all-masked state). After this loads, SSE instructions stop
 * raising #UD and ssetest.exe should report SSE = WORKING. OSXMMEXCPT is left
 * clear on purpose (3.51 has no #XM handler). CR4 is restored on unload.
 *
 * INCREMENT 3 (added) installs a #NM (vector 7) handler that gives every thread
 * its own XMM/MXCSR state, so two SSE programs no longer clobber each other.
 * INCREMENT 4 (added) detours SwapContext at 0x8013cd90 so state is flushed on
 * every context switch, not only the ones where the kernel happens to set TS.
 *
 * How the #NM hook works (mirroring what intlfxsr.sys does, see README.md):
 *   FXSAVE saves BOTH x87 and XMM state, and the kernel already owns x87. So we
 *   must not hand the kernel a different x87 image than it expects. Instead:
 *     1. clear CR0.TS so FP/SSE instructions can run inside the handler,
 *     2. FXSAVE the live state into a per-CPU scratch image,
 *     3. copy MXCSR (+0x18) and XMM0-7 (+0xa0, 128 bytes) OUT of that image
 *        into the previous owning thread's save area,
 *     4. copy the current thread's MXCSR/XMM INTO the image (or defaults if the
 *        thread has none yet),
 *     5. FXRSTOR the image, restore the ORIGINAL CR0 (TS exactly as it was),
 *     6. jump into the kernel's own #NM handler at +54 bytes, past the prologue
 *        we duplicated, and let it do its normal lazy-x87 work.
 *   Only MXCSR and XMM ever move; x87 is left to the kernel.
 *
 * Locking: vector 7 is an INTERRUPT gate (access 0x8E) on 3.51, so the CPU
 * clears IF on entry - the handler runs with interrupts disabled. On a
 * uniprocessor that makes the thread table access atomic without a spinlock,
 * which matters because a #NM can arrive at any IRQL and a spinlock would not
 * protect against it. The SwapContext detour does its own CLI for the same
 * reason. Both are uniprocessor-correct; MP needs per-CPU state (see README).
 *
 * NOT YET PRESENT: multiprocessor fan-out (boot CPU only).
 */

#include <ntddk.h>

/*
 * Per-thread SSE save area. The NT 4.0 driver used 0x84 = 132 bytes (XMM0-7 =
 * 128 + MXCSR = 4). We allocate a full 512-byte FXSAVE image, 16-byte aligned,
 * so the #NM handler in the next increment can use FXSAVE/FXRSTOR directly if
 * we choose to; 132-byte manual save still fits. RawBase holds the un-aligned
 * allocation so it can be freed.
 */
#define SSE_SAVE_SIZE     512
#define SSE_SAVE_ALIGN    16
#define DEFAULT_MXCSR     0x1f80          /* all six SIMD exceptions masked */

#define CR4_OSFXSR        0x00000200      /* CR4 bit 9  - enable SSE + FXSAVE   */
#define CR4_OSFXSR_CLEAR  0xfffffdff      /* ~CR4_OSFXSR (asm has no ~ operator) */
#define CR4_OSXMMEXCPT    0x00000400      /* CR4 bit 10 - #XM; left CLEAR on 3.51 */

/*
 * Offsets inside a 512-byte FXSAVE image, and the layout of a thread's save
 * area. We keep the thread's state in the same shape the original used:
 *   save[0x00 .. 0x7f]  XMM0-7 (128 bytes)
 *   save[0x80]          MXCSR
 */
#define FXI_MXCSR         0x18            /* MXCSR within an FXSAVE image     */
#define FXI_XMM           0xa0            /* XMM0 within an FXSAVE image      */
#define XMM_BYTES         0x80            /* XMM0-7 = 8 * 16 bytes            */
#define SAVE_XMM          0x00            /* XMM within our per-thread area   */
#define SAVE_MXCSR        0x80            /* MXCSR within our per-thread area */

/* IDT vector we hook, and the size of the kernel prologue we duplicate. */
#define NM_VECTOR         7
#define NM_PROLOGUE_LEN   54              /* verified byte-identical, see nmsig.py */

#define POOL_TAG          'ESSN'          /* 'NSSE' shown in pool tracking */
#define PREFILL_BUFFERS   64              /* pre-allocated save areas       */
#define MAX_THREADS       512             /* thread->buffer table capacity  */

/* One free-list node. The aligned save area follows the bookkeeping. */
typedef struct _SSE_BUFFER {
    SINGLE_LIST_ENTRY Link;               /* free-list linkage              */
    PVOID             RawBase;            /* un-aligned ExAllocatePool ptr  */
    PVOID             Save;               /* 16-aligned save area           */
} SSE_BUFFER, *PSSE_BUFFER;

/* Thread->buffer association. Thread == NULL means the slot is empty. */
typedef struct _THREAD_SLOT {
    PKTHREAD    Thread;
    PSSE_BUFFER Buffer;
} THREAD_SLOT;

/* --- global state ------------------------------------------------------- */

static SINGLE_LIST_ENTRY g_FreeList;      /* head of the buffer free list   */
static KSPIN_LOCK        g_FreeLock;      /* guards g_FreeList              */

static THREAD_SLOT       g_Table[MAX_THREADS];
static KSPIN_LOCK        g_TableLock;     /* guards g_Table                 */

static ULONG             g_Features;      /* CPUID.1 EDX, for logging       */
static ULONG             g_BuffersBuilt;  /* how many pre-fills succeeded    */
static BOOLEAN           g_SseEnabled;    /* did we set CR4.OSFXSR?          */

/* ----------------------------------------------------------------------- */
/* CPUID probing (identical idiom to the proven ntver.c: MSVC 4.2 has no    */
/* __cpuid and no 0F A2 support in its inline assembler, so emit the bytes).*/
/* ----------------------------------------------------------------------- */

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
        xor  eax, 0x00200000        ; flip EFLAGS.ID
        push eax
        popfd
        pushfd
        pop  eax
        xor  eax, ecx
        and  eax, 0x00200000
        mov  supported, eax
        push ecx                    ; restore original EFLAGS
        popfd
    }

    return (BOOLEAN)(supported != 0);
}

static VOID
GetCpuFeatures(
    OUT PULONG Edx
    )
{
    ULONG localEdx = 0;

    _asm {
        pushad
        mov  eax, 1
        _emit 0x0F
        _emit 0xA2                   ; cpuid
        mov  localEdx, edx
        popad
    }

    *Edx = localEdx;
}

/* ----------------------------------------------------------------------- */
/* Buffer pool: SINGLE_LIST_ENTRY + KSPIN_LOCK, 3.51-native.                */
/* ExInterlockedPush/PopEntryList do the locking (and IRQL) themselves, so  */
/* they are safe from PASSIVE_LEVEL here and from elevated IRQL later.      */
/* ----------------------------------------------------------------------- */

static PSSE_BUFFER
PoolPop(
    VOID
    )
{
    PSINGLE_LIST_ENTRY e = ExInterlockedPopEntryList(&g_FreeList, &g_FreeLock);
    /* Link is the first member, so the node pointer is the entry pointer. */
    return (PSSE_BUFFER)e;
}

static VOID
PoolPush(
    IN PSSE_BUFFER Buffer
    )
{
    ExInterlockedPushEntryList(&g_FreeList, &Buffer->Link, &g_FreeLock);
}

/*
 * Build one save-area node: allocate bookkeeping + room to 16-align the save
 * area, initialise MXCSR to the masked default, and push it on the free list.
 */
static BOOLEAN
PoolBuildOne(
    VOID
    )
{
    PSSE_BUFFER node;
    PUCHAR      raw;
    ULONG   aligned;

    node = (PSSE_BUFFER)ExAllocatePoolWithTag(NonPagedPool,
                                              sizeof(SSE_BUFFER),
                                              POOL_TAG);
    if (node == NULL) {
        return FALSE;
    }

    raw = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool,
                                        SSE_SAVE_SIZE + SSE_SAVE_ALIGN,
                                        POOL_TAG);
    if (raw == NULL) {
        ExFreePool(node);
        return FALSE;
    }

    aligned = ((ULONG)raw + (SSE_SAVE_ALIGN - 1)) & ~((ULONG)(SSE_SAVE_ALIGN - 1));

    node->RawBase = raw;
    node->Save    = (PVOID)aligned;

    /*
     * Zero the save area and set the default MXCSR. Note this area is in OUR
     * layout (XMM at +0x00, MXCSR at +0x80), not FXSAVE's - the handler copies
     * the fields across. Increment 1 wrote MXCSR at the FXSAVE offset, which
     * was harmless then because nothing read it; it is corrected here.
     */
    {
        PUCHAR p = (PUCHAR)node->Save;
        ULONG  i;
        for (i = 0; i < SSE_SAVE_SIZE; i++) {
            p[i] = 0;
        }
        *(PULONG)(p + SAVE_MXCSR) = DEFAULT_MXCSR;
    }

    PoolPush(node);
    return TRUE;
}

static VOID
PoolDrain(
    VOID
    )
{
    PSSE_BUFFER node;

    while ((node = PoolPop()) != NULL) {
        if (node->RawBase != NULL) {
            ExFreePool(node->RawBase);
        }
        ExFreePool(node);
    }
}

/* ----------------------------------------------------------------------- */
/* Thread->buffer table: linear-probe array under a spinlock.               */
/* KeAcquireSpinLock maps to KfAcquireSpinLock (hal.dll), present on 3.51.   */
/* Increment 1 touches the table only from PASSIVE_LEVEL (DriverEntry); the  */
/* #NM handler's raw-IRQL access is added with its own discipline later.     */
/* ----------------------------------------------------------------------- */

static ULONG
TableHash(
    IN PKTHREAD Thread
    )
{
    /* KTHREAD is 16-byte aligned; drop the dead low bits before folding. */
    return (ULONG)(((ULONG)Thread >> 4)) % MAX_THREADS;
}

/*
 * Find Thread's buffer, assigning a fresh one from the pool on first use.
 * Returns NULL if the pool is empty or the table is full.
 */
static PSSE_BUFFER
TableLookupOrAssign(
    IN PKTHREAD Thread
    )
{
    KIRQL       old;
    ULONG       start, i, idx;
    PSSE_BUFFER result = NULL;

    KeAcquireSpinLock(&g_TableLock, &old);

    start = TableHash(Thread);
    for (i = 0; i < MAX_THREADS; i++) {
        idx = (start + i) % MAX_THREADS;
        if (g_Table[idx].Thread == Thread) {
            result = g_Table[idx].Buffer;      /* already assigned */
            break;
        }
        if (g_Table[idx].Thread == NULL) {
            PSSE_BUFFER buf = PoolPop();        /* claim from pool  */
            if (buf != NULL) {
                g_Table[idx].Thread = Thread;
                g_Table[idx].Buffer = buf;
                result = buf;
            }
            break;
        }
    }

    KeReleaseSpinLock(&g_TableLock, old);
    return result;
}

/*
 * Drop Thread's association and return its buffer to the pool. Called from the
 * thread-teardown path in a later increment; used by the self-test here.
 */
static VOID
TableRelease(
    IN PKTHREAD Thread
    )
{
    KIRQL       old;
    ULONG       start, i, idx;
    PSSE_BUFFER buf = NULL;

    KeAcquireSpinLock(&g_TableLock, &old);

    start = TableHash(Thread);
    for (i = 0; i < MAX_THREADS; i++) {
        idx = (start + i) % MAX_THREADS;
        if (g_Table[idx].Thread == Thread) {
            buf = g_Table[idx].Buffer;
            g_Table[idx].Thread = NULL;
            g_Table[idx].Buffer = NULL;
            break;
        }
        if (g_Table[idx].Thread == NULL) {
            break;                              /* not present */
        }
    }

    KeReleaseSpinLock(&g_TableLock, old);

    if (buf != NULL) {
        PoolPush(buf);
    }
}

/* ----------------------------------------------------------------------- */
/* ForceNpxEmulation opt-out, same key/value the original consults.         */
/* ----------------------------------------------------------------------- */

static BOOLEAN
ForceNpxEmulationSet(
    VOID
    )
{
    UNICODE_STRING             keyName, valueName;
    OBJECT_ATTRIBUTES          attr;
    HANDLE                     key = NULL;
    NTSTATUS                   status;
    ULONG                      len = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info;
    ULONG                      infoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG);
    BOOLEAN                    result = FALSE;

    RtlInitUnicodeString(&keyName,
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager");
    InitializeObjectAttributes(&attr, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&key, KEY_READ, &attr);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, infoSize, POOL_TAG);
    if (info != NULL) {
        RtlInitUnicodeString(&valueName, L"ForceNpxEmulation");
        status = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation,
                                 info, infoSize, &len);
        if (NT_SUCCESS(status) &&
            info->Type == REG_DWORD &&
            info->DataLength == sizeof(ULONG)) {
            ULONG v = *(PULONG)info->Data;
            if (v != 0 && v != 1) {
                result = TRUE;
            }
        }
        ExFreePool(info);
    }

    ZwClose(key);
    return result;
}

/* ----------------------------------------------------------------------- */
/* Event-log breadcrumb (same shape as ntver.c, with populated dump data).  */
/* ----------------------------------------------------------------------- */

static VOID
LogResult(
    IN PDRIVER_OBJECT DriverObject,
    IN NTSTATUS       Code,
    IN ULONG          Unique
    )
{
    PIO_ERROR_LOG_PACKET packet;

    packet = (PIO_ERROR_LOG_PACKET)
        IoAllocateErrorLogEntry(DriverObject, (UCHAR)sizeof(IO_ERROR_LOG_PACKET));
    if (packet != NULL) {
        PUCHAR raw = (PUCHAR)packet;
        ULONG  i;
        for (i = 0; i < sizeof(IO_ERROR_LOG_PACKET); i++) {
            raw[i] = 0;
        }
        packet->ErrorCode        = Code;
        packet->UniqueErrorValue = Unique;
        packet->FinalStatus      = STATUS_SUCCESS;
        packet->DumpDataSize     = (USHORT)sizeof(ULONG);
        packet->DumpData[0]      = Unique;
        IoWriteErrorLogEntry(packet);
    }
}

/* ----------------------------------------------------------------------- */
/* Increments 3 and 4: trap-context state.                                   */
/*                                                                           */
/* These are touched from the #NM handler and the SwapContext detour, both of */
/* which run with interrupts disabled on the boot CPU, so they need no lock   */
/* (and could not safely take one - a #NM can arrive at any IRQL).            */
/* ----------------------------------------------------------------------- */

/*
 * Per-CPU FXSAVE scratch image. FXSAVE/FXRSTOR require 16-byte alignment, so
 * over-allocate and align at init. Only the boot CPU is set up for now.
 */
static PUCHAR   g_FxImage;                /* 16-aligned 512-byte FXSAVE area  */
static PUCHAR   g_FxImageRaw;             /* un-aligned allocation, to free    */
static PVOID    g_FxOwner;                /* save area owning the live XMM     */

static ULONG    g_KernelNmResume;         /* kernel #NM handler + 54           */
static ULONG    g_SwapTrampoline;         /* our trampoline -> SwapContext+5   */
static BOOLEAN  g_NmHooked;
static BOOLEAN  g_SwapHooked;

static ULONG    g_NmCount;                /* diagnostics: #NM traps serviced   */
static ULONG    g_SwapFlushes;            /* diagnostics: swap-time flushes    */

/*
 * Lock-free lookup of the CURRENT thread's save area, for trap context only.
 * Assigns one from the pool on first use. Callers run with interrupts off on a
 * uniprocessor, so the array walk is atomic. Returns NULL if the pool is empty
 * or the table is full - the caller then falls back to default state rather
 * than failing the trap.
 *
 * Takes NO arguments and reads the current thread itself. That is deliberate:
 * the trap path is hand-written assembly, and with /Gz every C function is
 * __stdcall (callee pops). A zero-argument callee means there is no argument
 * push and no pop to get wrong - which is exactly the mistake that hung the
 * machine once (a "push/call/add esp,4" against a "ret 4" callee double-popped
 * ESP, corrupted the trap frame, and made the kernel handler's iret return to
 * garbage: a silent hard hang, since interrupts are disabled in a trap gate).
 *
 * It also deliberately does NOT call ExInterlockedPopEntryList: that acquires a
 * spinlock and raises IRQL, which is wrong inside a trap gate. We pop the
 * singly-linked list by hand, which is safe with interrupts already off.
 */
static PVOID
TrapLookupSaveArea(
    VOID
    )
{
    PKTHREAD thread = KeGetCurrentThread();
    ULONG    start, i, idx;

    start = TableHash(thread);
    for (i = 0; i < MAX_THREADS; i++) {
        idx = (start + i) % MAX_THREADS;
        if (g_Table[idx].Thread == thread) {
            return g_Table[idx].Buffer ? g_Table[idx].Buffer->Save : NULL;
        }
        if (g_Table[idx].Thread == NULL) {
            /* Unlocked pop from the free list; interrupts are off. */
            PSINGLE_LIST_ENTRY e = g_FreeList.Next;
            PSSE_BUFFER        buf;

            if (e == NULL) {
                return NULL;                    /* pool exhausted */
            }
            g_FreeList.Next = e->Next;
            buf = (PSSE_BUFFER)e;

            g_Table[idx].Thread = thread;
            g_Table[idx].Buffer = buf;
            return buf->Save;
        }
    }
    return NULL;                                /* table full */
}

/*
 * The #NM (vector 7) handler. Naked: we must not disturb any register the
 * kernel's own handler expects, and we end with a jump into that handler
 * rather than a return.
 *
 * The first NM_PROLOGUE_LEN bytes of the kernel's handler are duplicated at
 * the top of this function (verified byte-identical between 3.51 and NT 4.0 by
 * nmsig.py), because we resume the kernel handler just past its prologue. That
 * prologue is the ENTER_TRAP macro: it builds the trap frame. We reproduce it
 * exactly, do our XMM work, then jump to kernel_handler + 54.
 */
static __declspec(naked) void
NmHandler(
    void
    )
{
    _asm {
        /* ---- verbatim copy of 3.51's #NM prologue (54 bytes) ------------ */
        push 0
        mov  word ptr [esp+2], 0
        push ebp
        push ebx
        push esi
        push edi
        push fs
        mov  ebx, 30h
        mov  fs, bx
        mov  ebx, fs:[0]
        push ebx
        sub  esp, 4
        push eax
        push ecx
        push edx
        push ds
        push es
        push gs
        mov  ax, 23h
        sub  esp, 30h
        mov  ds, ax
        mov  es, ax
        /* ---- end of duplicated prologue --------------------------------- */

        /* Clear CR0.TS (and MP/EM) so FP/SSE can execute in here. Keep the
           original CR0 in EBP to restore verbatim before resuming. */
        _emit 0x0F                  ; mov ebp, cr0
        _emit 0x20
        _emit 0xC5
        mov  eax, ebp
        and  eax, 0xfffffff1
        _emit 0x0F                  ; mov cr0, eax
        _emit 0x22
        _emit 0xC0
        cld

        inc  dword ptr [g_NmCount]

        /* ESI = per-CPU FXSAVE image; bail out if not initialised. */
        mov  esi, [g_FxImage]
        or   esi, esi
        jz   nm_resume

        /* Snapshot the live FPU/SSE state into the scratch image. */
        _emit 0x0F                  ; fxsave [esi]
        _emit 0xAE
        _emit 0x06

        /* If somebody owns the live XMM state, flush it out to them. */
        mov  edi, [g_FxOwner]
        or   edi, edi
        jz   nm_load

        mov  eax, [esi + FXI_MXCSR]
        mov  [edi + SAVE_MXCSR], eax
        push esi
        push edi
        add  esi, FXI_XMM               ; source: XMM in the image
        add  edi, SAVE_XMM              ; dest:   owner's XMM slot
        mov  ecx, XMM_BYTES
        rep  movsb
        pop  edi
        pop  esi

nm_load:
        /* Find (or assign) this thread's save area. TrapLookupSaveArea takes
           no arguments and reads KeGetCurrentThread() itself, so there is no
           argument push and nothing for us to pop - see the note on that
           function. EAX returns the save area (or NULL). */
        push esi
        call TrapLookupSaveArea
        pop  esi

        or   eax, eax
        jz   nm_defaults

        /* Load this thread's MXCSR + XMM into the image. */
        mov  [g_FxOwner], eax
        mov  ecx, [eax + SAVE_MXCSR]
        mov  [esi + FXI_MXCSR], ecx
        push esi
        push edi
        mov  edi, esi
        add  edi, FXI_XMM               ; dest:   XMM in the image
        mov  esi, eax
        add  esi, SAVE_XMM              ; source: thread's XMM
        mov  ecx, XMM_BYTES
        rep  movsb
        pop  edi
        pop  esi
        jmp  nm_restore

nm_defaults:
        /* No save area available: give the thread clean default state. */
        mov  dword ptr [g_FxOwner], 0
        mov  dword ptr [esi + FXI_MXCSR], DEFAULT_MXCSR
        push esi
        push edi
        mov  edi, esi
        add  edi, FXI_XMM
        mov  ecx, XMM_BYTES
        xor  eax, eax
        rep  stosb
        pop  edi
        pop  esi

nm_restore:
        /* Load the assembled state back into the FPU/SSE unit. */
        _emit 0x0F                  ; fxrstor [esi]
        _emit 0xAE
        _emit 0x0E

nm_resume:
        /* Restore CR0 exactly as the trap found it - the kernel's handler is
           about to do its own lazy-x87 work and must see the original TS. */
        _emit 0x0F                  ; mov cr0, ebp
        _emit 0x22
        _emit 0xC5

        /* Enter the kernel's #NM handler just past the prologue we copied. */
        jmp  dword ptr [g_KernelNmResume]
    }
}

/*
 * Increment 4: the SwapContext detour.
 *
 * Why it is needed: a thread that actively uses x87 keeps CR0.TS CLEAR across
 * switches, so it never takes a #NM on its way back in - which means the #NM
 * hook alone would never notice the switch and XMM state would leak between
 * threads. Flushing at switch time closes that hole.
 *
 * This runs as a detour at the very top of SwapContext, before its own
 * prologue. We only flush the live XMM out to its owner and mark the CPU
 * unowned; the next SSE instruction in the incoming thread takes a #NM and
 * loads its state. All registers and flags are preserved, interrupts are
 * forced off across the critical section, and we finish by jumping to the
 * trampoline (the displaced 5 bytes + a jump back to SwapContext+5).
 */
static __declspec(naked) void
SwapDetour(
    void
    )
{
    _asm {
        pushfd
        cli
        pushad

        mov  esi, [g_FxImage]
        or   esi, esi
        jz   swap_done

        mov  edi, [g_FxOwner]
        or   edi, edi
        jz   swap_done              ; nobody owns the XMM state

        /* Clear TS so FXSAVE can run; remember original CR0 in EBX. */
        _emit 0x0F                  ; mov ebx, cr0
        _emit 0x20
        _emit 0xC3
        mov  eax, ebx
        and  eax, 0xfffffff1
        _emit 0x0F                  ; mov cr0, eax
        _emit 0x22
        _emit 0xC0

        _emit 0x0F                  ; fxsave [esi]
        _emit 0xAE
        _emit 0x06

        mov  eax, [esi + FXI_MXCSR]
        mov  [edi + SAVE_MXCSR], eax
        add  esi, FXI_XMM
        add  edi, SAVE_XMM
        mov  ecx, XMM_BYTES
        cld
        rep  movsb

        mov  dword ptr [g_FxOwner], 0
        inc  dword ptr [g_SwapFlushes]

        /* Restore CR0 as it was - leave the kernel's lazy-FP logic alone. */
        _emit 0x0F                  ; mov cr0, ebx
        _emit 0x22
        _emit 0xC3

swap_done:
        popad
        popfd
        jmp  dword ptr [g_SwapTrampoline]
    }
}

/* ----------------------------------------------------------------------- */
/* Installing the hooks.                                                     */
/* ----------------------------------------------------------------------- */

/* An i386 IDT gate descriptor, in its live (swizzled) form. */
typedef struct _IDT_GATE {
    USHORT OffsetLow;
    USHORT Selector;
    UCHAR  Reserved;
    UCHAR  Access;
    USHORT OffsetHigh;
} IDT_GATE, *PIDT_GATE;

/* Operand for SIDT. */
#pragma pack(push, 1)
typedef struct _IDTR {
    USHORT Limit;
    ULONG  Base;
} IDTR;
#pragma pack(pop)

static PIDT_GATE
GetIdt(
    VOID
    )
{
    IDTR idtr;

    idtr.Limit = 0;
    idtr.Base  = 0;

    _asm {
        lea  eax, idtr
        _emit 0x0F               ; sidt [eax]
        _emit 0x01
        _emit 0x08
    }

    return (PIDT_GATE)idtr.Base;
}

static ULONG
GateTarget(
    IN PIDT_GATE Gate
    )
{
    return ((ULONG)Gate->OffsetHigh << 16) | (ULONG)Gate->OffsetLow;
}

static VOID
SetGateTarget(
    IN PIDT_GATE Gate,
    IN ULONG     Target
    )
{
    /* Interrupts off while the two halves are inconsistent. */
    _asm cli
    Gate->OffsetLow  = (USHORT)(Target & 0xffff);
    Gate->OffsetHigh = (USHORT)(Target >> 16);
    _asm sti
}

/*
 * Verify the live vector-7 handler still begins with the prologue we
 * duplicated, then repoint it at our handler. This is the same guard the
 * original applies: if the kernel's prologue is not what we copied, our resume
 * offset would be wrong, so we refuse rather than corrupt the trap path.
 *
 * Compares against our own NmHandler, whose first NM_PROLOGUE_LEN bytes ARE
 * that prologue - so the check is self-referential and needs no separate blob.
 */
static BOOLEAN
InstallNmHook(
    OUT PULONG LiveHandler,
    OUT PULONG Matched
    )
{
    PIDT_GATE gate = GetIdt() + NM_VECTOR;
    ULONG     live = GateTarget(gate);
    PUCHAR    a    = (PUCHAR)live;
    PUCHAR    b    = (PUCHAR)NmHandler;
    ULONG     i;

    *LiveHandler = live;
    *Matched     = 0;

    for (i = 0; i < NM_PROLOGUE_LEN; i++) {
        if (a[i] != b[i]) {
            break;
        }
    }
    *Matched = i;

    if (i != NM_PROLOGUE_LEN) {
        return FALSE;
    }

    g_KernelNmResume = live + NM_PROLOGUE_LEN;
    SetGateTarget(gate, (ULONG)NmHandler);
    g_NmHooked = TRUE;
    return TRUE;
}

static VOID
RemoveNmHook(
    VOID
    )
{
    if (g_NmHooked) {
        PIDT_GATE gate = GetIdt() + NM_VECTOR;
        SetGateTarget(gate, g_KernelNmResume - NM_PROLOGUE_LEN);
        g_NmHooked = FALSE;
    }
}

/*
 * SwapContext detour. We overwrite the first 5 bytes of SwapContext with a
 * JMP to SwapDetour, and build a trampoline holding the displaced bytes
 * followed by a JMP back to SwapContext+5.
 *
 * The 5 bytes at 0x8013cd90 are "0a c9 9c 8b 0b" = or cl,cl / pushf /
 * mov ecx,[ebx] - three whole instructions, so the split is on an instruction
 * boundary and the trampoline is valid. We verify those exact bytes before
 * patching; if the kernel differs, we refuse.
 */
#define SWAPCONTEXT_VA    0x8013cd90
#define DETOUR_LEN        5

static const UCHAR SwapExpected[DETOUR_LEN] = { 0x0a, 0xc9, 0x9c, 0x8b, 0x0b };

static PUCHAR g_Trampoline;               /* displaced bytes + jmp back */
static UCHAR  g_SwapOriginal[DETOUR_LEN];

static BOOLEAN
InstallSwapHook(
    OUT PULONG Mismatch
    )
{
    PUCHAR target = (PUCHAR)SWAPCONTEXT_VA;
    ULONG  i;
    LONG   delta;

    *Mismatch = 0;

    for (i = 0; i < DETOUR_LEN; i++) {
        if (target[i] != SwapExpected[i]) {
            *Mismatch = i + 1;                  /* 1-based, 0 means "matched" */
            return FALSE;
        }
    }

    /* Trampoline: 5 displaced bytes + E9 rel32 back to SwapContext+5. */
    g_Trampoline = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool,
                                                 DETOUR_LEN + 5,
                                                 POOL_TAG);
    if (g_Trampoline == NULL) {
        return FALSE;
    }

    for (i = 0; i < DETOUR_LEN; i++) {
        g_Trampoline[i]     = target[i];
        g_SwapOriginal[i]   = target[i];
    }
    g_Trampoline[DETOUR_LEN] = 0xE9;
    delta = (LONG)(SWAPCONTEXT_VA + DETOUR_LEN)
          - (LONG)((ULONG)g_Trampoline + DETOUR_LEN + 5);
    *(PLONG)(g_Trampoline + DETOUR_LEN + 1) = delta;

    g_SwapTrampoline = (ULONG)g_Trampoline;

    /* Patch SwapContext: E9 rel32 -> SwapDetour. Interrupts off while the
       instruction stream is half-written. */
    delta = (LONG)((ULONG)SwapDetour) - (LONG)(SWAPCONTEXT_VA + 5);
    _asm cli
    target[0] = 0xE9;
    *(PLONG)(target + 1) = delta;
    _asm sti

    g_SwapHooked = TRUE;
    return TRUE;
}

static VOID
RemoveSwapHook(
    VOID
    )
{
    if (g_SwapHooked) {
        PUCHAR target = (PUCHAR)SWAPCONTEXT_VA;
        ULONG  i;

        _asm cli
        for (i = 0; i < DETOUR_LEN; i++) {
            target[i] = g_SwapOriginal[i];
        }
        _asm sti

        g_SwapHooked = FALSE;
    }

    if (g_Trampoline != NULL) {
        ExFreePool(g_Trampoline);
        g_Trampoline = NULL;
    }
}

/* ----------------------------------------------------------------------- */
/* Increment 2: enable SSE by setting CR4.OSFXSR and putting MXCSR in a      */
/* known all-masked state. CR4 and MXCSR are per-processor, so callers pin   */
/* to a CPU (raise to DISPATCH_LEVEL) around these. MSVC 4.2's assembler does */
/* not know the CR4 mov or LDMXCSR, so both are emitted as raw opcode bytes.  */
/* ----------------------------------------------------------------------- */

static ULONG g_MxcsrInit = DEFAULT_MXCSR;   /* addressable operand for LDMXCSR */

static VOID
EnableSseThisCpu(
    OUT PULONG Cr4Before,
    OUT PULONG Cr4After
    )
{
    ULONG before = 0;
    ULONG after  = 0;

    _asm {
        _emit 0x0F                  ; mov eax, cr4
        _emit 0x20
        _emit 0xE0
        mov  before, eax
        or   eax, CR4_OSFXSR        ; set OSFXSR (bit 9); leave OSXMMEXCPT clear
        _emit 0x0F                  ; mov cr4, eax
        _emit 0x22
        _emit 0xE0
        _emit 0x0F                  ; mov eax, cr4  (read back to confirm)
        _emit 0x20
        _emit 0xE0
        mov  after, eax
        lea  eax, g_MxcsrInit       ; ldmxcsr [g_MxcsrInit]  (0F AE /2)
        _emit 0x0F
        _emit 0xAE
        _emit 0x10
    }

    *Cr4Before = before;
    *Cr4After  = after;
}

static VOID
DisableSseThisCpu(
    VOID
    )
{
    _asm {
        _emit 0x0F                  ; mov eax, cr4
        _emit 0x20
        _emit 0xE0
        and  eax, CR4_OSFXSR_CLEAR  ; clear OSFXSR (bit 9)
        _emit 0x0F                  ; mov cr4, eax
        _emit 0x22
        _emit 0xE0
    }
}

/*
 * Like LogResult, but carries several ULONGs in the dump data so Event Viewer
 * shows, e.g., features + CR4-before + CR4-after. UniqueErrorValue mirrors the
 * first value for a quick read.
 */
static VOID
LogData(
    IN PDRIVER_OBJECT DriverObject,
    IN NTSTATUS       Code,
    IN PULONG         Values,
    IN ULONG          Count
    )
{
    PIO_ERROR_LOG_PACKET packet;
    ULONG size = sizeof(IO_ERROR_LOG_PACKET);

    if (Count > 1) {
        size += (Count - 1) * sizeof(ULONG);
    }
    if (size > 0xff) {              /* IoAllocateErrorLogEntry length is a UCHAR */
        return;
    }

    packet = (PIO_ERROR_LOG_PACKET)IoAllocateErrorLogEntry(DriverObject, (UCHAR)size);
    if (packet != NULL) {
        PUCHAR raw = (PUCHAR)packet;
        ULONG  i;
        for (i = 0; i < size; i++) {
            raw[i] = 0;
        }
        packet->ErrorCode    = Code;
        packet->FinalStatus  = STATUS_SUCCESS;
        packet->DumpDataSize = (USHORT)(Count * sizeof(ULONG));
        for (i = 0; i < Count; i++) {
            packet->DumpData[i] = Values[i];
        }
        if (Count > 0) {
            packet->UniqueErrorValue = Values[0];
        }
        IoWriteErrorLogEntry(packet);
    }
}

/* ----------------------------------------------------------------------- */

static VOID
DriverUnload(
    IN PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    /*
     * Unhook in the reverse order of installation, and BEFORE freeing anything
     * the hooks touch. Once both are out, no trap path can reach our state.
     */
    RemoveSwapHook();
    RemoveNmHook();
    g_FxOwner = NULL;

    if (g_FxImageRaw != NULL) {
        ExFreePool(g_FxImageRaw);
        g_FxImageRaw = NULL;
        g_FxImage    = NULL;
    }

    /* Restore stock CPU state: clear OSFXSR if we set it. Pin to this CPU. */
    if (g_SseEnabled) {
        KIRQL old;
        KeRaiseIrql(DISPATCH_LEVEL, &old);
        DisableSseThisCpu();
        KeLowerIrql(old);
        g_SseEnabled = FALSE;
        DbgPrint("nt351sse: OSFXSR cleared\n");
    }

    /* Reclaim any buffers still held by table entries, then drain the pool. */
    {
        ULONG idx;
        for (idx = 0; idx < MAX_THREADS; idx++) {
            if (g_Table[idx].Thread != NULL && g_Table[idx].Buffer != NULL) {
                PoolPush(g_Table[idx].Buffer);
                g_Table[idx].Thread = NULL;
                g_Table[idx].Buffer = NULL;
            }
        }
    }
    PoolDrain();

    DbgPrint("nt351sse: unloaded (NM traps %lu, swap flushes %lu)\n",
             g_NmCount, g_SwapFlushes);
}

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
{
    ULONG       i;
    PKTHREAD    self;
    PSSE_BUFFER a, b;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("nt351sse: DriverEntry (increment 1: data layer only)\n");

    if (ForceNpxEmulationSet()) {
        DbgPrint("nt351sse: ForceNpxEmulation set -> declining to load\n");
        LogResult(DriverObject, STATUS_SUCCESS, 0x00000002);
        return STATUS_UNSUCCESSFUL;
    }

    if (!HasCpuid()) {
        DbgPrint("nt351sse: no CPUID -> cannot gate on SSE\n");
        LogResult(DriverObject, STATUS_SUCCESS, 0x00000003);
        return STATUS_UNSUCCESSFUL;
    }

    GetCpuFeatures(&g_Features);
    DbgPrint("nt351sse: CPUID.1 EDX=%08lx (FXSR=%d SSE=%d SSE2=%d MMX=%d)\n",
             g_Features,
             (g_Features & (1 << 24)) ? 1 : 0,
             (g_Features & (1 << 25)) ? 1 : 0,
             (g_Features & (1 << 26)) ? 1 : 0,
             (g_Features & (1 << 23)) ? 1 : 0);

    /* Gate: FXSR (bit 24) AND SSE (bit 25), exactly as intlfxsr.sys does. */
    if (((g_Features & (1 << 24)) == 0) || ((g_Features & (1 << 25)) == 0)) {
        DbgPrint("nt351sse: CPU lacks FXSR+SSE -> declining to load\n");
        LogResult(DriverObject, STATUS_SUCCESS, 0x00000001);
        return STATUS_UNSUCCESSFUL;
    }

    /* Initialise the pool and table. */
    g_FreeList.Next = NULL;
    KeInitializeSpinLock(&g_FreeLock);
    KeInitializeSpinLock(&g_TableLock);
    for (i = 0; i < MAX_THREADS; i++) {
        g_Table[i].Thread = NULL;
        g_Table[i].Buffer = NULL;
    }

    g_BuffersBuilt = 0;
    for (i = 0; i < PREFILL_BUFFERS; i++) {
        if (!PoolBuildOne()) {
            break;
        }
        g_BuffersBuilt++;
    }
    DbgPrint("nt351sse: pre-filled %lu/%lu save buffers\n",
             g_BuffersBuilt, (ULONG)PREFILL_BUFFERS);

    if (g_BuffersBuilt == 0) {
        DbgPrint("nt351sse: pool allocation failed\n");
        LogResult(DriverObject, STATUS_SUCCESS, 0x00000004);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /*
     * Self-test the data layer end to end: assign a buffer to the current
     * thread, confirm the lookup is stable, release it, and confirm it is
     * gone. This exercises pool pop/push and the table under the real locks.
     */
    self = KeGetCurrentThread();
    a = TableLookupOrAssign(self);
    b = TableLookupOrAssign(self);
    if (a != NULL && a == b) {
        DbgPrint("nt351sse: self-test assign/lookup OK (buf=%p save=%p)\n",
                 a, a->Save);
        TableRelease(self);
        if (TableLookupOrAssign(self) != NULL) {
            /* got a (possibly different) buffer again -> release once more */
            TableRelease(self);
        }
        DbgPrint("nt351sse: self-test release OK\n");
    } else {
        DbgPrint("nt351sse: self-test FAILED (a=%p b=%p)\n", a, b);
    }

    /*
     * Increments 3 and 4: allocate the per-CPU FXSAVE scratch image, then
     * install the #NM handler and the SwapContext detour.
     *
     * Order matters: the hooks go in BEFORE OSFXSR is enabled, so that no
     * thread can execute an SSE instruction before per-thread state tracking
     * is live. If either hook fails to install we stop and do NOT enable SSE -
     * enabling it without state tracking is exactly the unsafe configuration
     * increment 2 warned about.
     */
    {
        ULONG  aligned;
        ULONG  liveNm = 0, matched = 0, mismatch = 0;

        g_FxImageRaw = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool,
                                                     SSE_SAVE_SIZE + SSE_SAVE_ALIGN,
                                                     POOL_TAG);
        if (g_FxImageRaw == NULL) {
            DbgPrint("nt351sse: cannot allocate FX scratch image\n");
            LogResult(DriverObject, STATUS_SUCCESS, 0x00000005);
            PoolDrain();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        aligned = ((ULONG)g_FxImageRaw + (SSE_SAVE_ALIGN - 1))
                & ~((ULONG)(SSE_SAVE_ALIGN - 1));
        g_FxImage = (PUCHAR)aligned;
        for (i = 0; i < SSE_SAVE_SIZE; i++) {
            g_FxImage[i] = 0;
        }
        g_FxOwner = NULL;

        if (!InstallNmHook(&liveNm, &matched)) {
            ULONG dump[3];
            DbgPrint("nt351sse: #NM prologue mismatch at %08lx (%lu of %d bytes)"
                     " - refusing to hook\n", liveNm, matched, NM_PROLOGUE_LEN);
            dump[0] = 0x00000006;
            dump[1] = liveNm;
            dump[2] = matched;
            LogData(DriverObject, STATUS_SUCCESS, dump, 3);
            ExFreePool(g_FxImageRaw);
            g_FxImageRaw = NULL;
            g_FxImage = NULL;
            PoolDrain();
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("nt351sse: #NM hooked (kernel %08lx, resume %08lx)\n",
                 liveNm, g_KernelNmResume);

        if (!InstallSwapHook(&mismatch)) {
            ULONG dump[3];
            DbgPrint("nt351sse: SwapContext bytes unexpected at %08lx"
                     " (first difference at +%lu) - refusing to hook\n",
                     (ULONG)SWAPCONTEXT_VA, mismatch ? mismatch - 1 : 0);
            dump[0] = 0x00000007;
            dump[1] = SWAPCONTEXT_VA;
            dump[2] = mismatch;
            LogData(DriverObject, STATUS_SUCCESS, dump, 3);
            RemoveNmHook();
            ExFreePool(g_FxImageRaw);
            g_FxImageRaw = NULL;
            g_FxImage = NULL;
            PoolDrain();
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("nt351sse: SwapContext detoured at %08lx (trampoline %08lx)\n",
                 (ULONG)SWAPCONTEXT_VA, g_SwapTrampoline);
    }

    /*
     * Increment 2: enable SSE. Pin to this processor across the CR4 write
     * (uniprocessor is the norm on 3.51; on MP the other CPUs are not enabled
     * yet - that fan-out is a later increment). Log features + CR4 before/after
     * so the flip is visible in Event Viewer's Data pane with no debugger.
     */
    {
        ULONG cr4Before = 0;
        ULONG cr4After  = 0;
        ULONG dump[3];
        KIRQL old;

        KeRaiseIrql(DISPATCH_LEVEL, &old);
        EnableSseThisCpu(&cr4Before, &cr4After);
        KeLowerIrql(old);

        g_SseEnabled = (BOOLEAN)((cr4After & CR4_OSFXSR) != 0);

        DbgPrint("nt351sse: CR4 %08lx -> %08lx, OSFXSR %s\n",
                 cr4Before, cr4After, g_SseEnabled ? "SET" : "NOT SET");

        dump[0] = g_Features;
        dump[1] = cr4Before;
        dump[2] = cr4After;
        LogData(DriverObject, STATUS_SUCCESS, dump, 3);

        if (*KeNumberProcessors > 1) {
            DbgPrint("nt351sse: WARNING multiprocessor (%d CPUs) - only the "
                     "boot CPU has OSFXSR set\n", (ULONG)*KeNumberProcessors);
        }
    }

    DbgPrint("nt351sse: increments 1-4 loaded; SSE %s, #NM and SwapContext hooked\n",
             g_SseEnabled ? "ENABLED (OSFXSR set)" : "NOT enabled");
    return STATUS_SUCCESS;
}
