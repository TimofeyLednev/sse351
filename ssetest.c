/*
 * ssetest.c - Does SSE/SSE2/MMX actually execute on this machine?
 *
 * A user-mode console acceptance test for the NT 3.51 SSE project. It is a
 * black box: it asks the CPU (via CPUID) what it *supports*, then actually
 * *executes* an MMX, an SSE, and an SSE2 instruction sequence and checks the
 * arithmetic. Each execution is wrapped in structured exception handling, so
 * an instruction the OS has not enabled faults cleanly and is reported as
 * FAULTED instead of killing the program.
 *
 * Why this matters here:
 *   - Stock NT 3.51 never sets CR4.OSFXSR, so an SSE instruction raises #UD
 *     (illegal instruction) even on a CPU that fully supports SSE. So on a
 *     stock 3.51 box you should see: CPU supports SSE = yes, SSE execution =
 *     FAULTED. That is the baseline.
 *   - MMX needs no OSFXSR (it aliases the x87 stack the kernel already saves),
 *     so MMX should already execute on 3.51.
 *   - Once the nt351sse driver enables SSE (a later increment), the SSE and
 *     SSE2 lines should flip from FAULTED to WORKING. That flip is the whole
 *     point of the project, and this program is how you see it.
 *
 * Built with MSVC 4.2. That compiler predates MMX and SSE, so its inline
 * assembler knows neither CPUID nor any SIMD mnemonic; every such instruction
 * is emitted as raw opcode bytes with _emit, exactly as the driver does.
 *
 * Build: BUILDTEST.BAT   ->   ssetest.exe (restamped to NT 3.51)
 */

#include <windows.h>
#include <stdio.h>

#define R_FAULTED 0     /* the instruction raised an exception   */
#define R_OK      1     /* executed and produced the right answer */
#define R_WRONG   2     /* executed but the answer was wrong      */

/* CPUID feature bits in leaf 1 EDX. */
#define FEAT_MMX  (1u << 23)
#define FEAT_FXSR (1u << 24)
#define FEAT_SSE  (1u << 25)
#define FEAT_SSE2 (1u << 26)

/*
 * CPUID presence test: try to toggle EFLAGS.ID (bit 21). If it will not flip,
 * the CPU is a 386/early 486 with no CPUID.
 */
static int
HasCpuid(void)
{
    unsigned int supported = 0;

    _asm {
        pushfd
        pop  eax
        mov  ecx, eax
        xor  eax, 0x00200000
        push eax
        popfd
        pushfd
        pop  eax
        xor  eax, ecx
        and  eax, 0x00200000
        mov  supported, eax
        push ecx
        popfd
    }

    return supported != 0;
}

/*
 * Execute CPUID for the given leaf, returning EAX/EBX/ECX/EDX. EBX is
 * callee-saved, so preserve it around the instruction.
 */
static void
DoCpuid(unsigned int leaf, unsigned int regs[4])
{
    unsigned int a = 0, b = 0, c = 0, d = 0;

    _asm {
        push ebx
        mov  eax, leaf
        _emit 0x0F
        _emit 0xA2              ; cpuid
        mov  a, eax
        mov  b, ebx
        mov  c, ecx
        mov  d, edx
        pop  ebx
    }

    regs[0] = a; regs[1] = b; regs[2] = c; regs[3] = d;
}

/*
 * MMX: r = a paddd b, on two packed dwords. Needs no OSFXSR; should already
 * work on NT 3.51. EMMS afterward so the x87 state is clean for the CRT.
 */
static int
TestMmx(void)
{
    unsigned int a[2], b[2], r[2];

    a[0] = 1;  a[1] = 2;
    b[0] = 10; b[1] = 20;
    r[0] = 0;  r[1] = 0;

    __try {
        _asm {
            lea eax, a
            lea ecx, b
            lea edx, r
            _emit 0x0F           ; movq mm0, [eax]
            _emit 0x6F
            _emit 0x00
            _emit 0x0F           ; movq mm1, [ecx]
            _emit 0x6F
            _emit 0x09
            _emit 0x0F           ; paddd mm0, mm1
            _emit 0xFE
            _emit 0xC1
            _emit 0x0F           ; movq [edx], mm0
            _emit 0x7F
            _emit 0x02
            _emit 0x0F           ; emms
            _emit 0x77
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return R_FAULTED;
    }

    if (r[0] == 11 && r[1] == 22)
        return R_OK;
    return R_WRONG;
}

/*
 * SSE: r = a addps b, on four packed floats. Uses MOVUPS (unaligned) so the
 * stack arrays need no 16-byte alignment. Faults on stock 3.51 (OSFXSR clear).
 */
static int
TestSse(void)
{
    float a[4], b[4], r[4];

    a[0] = 1.0f;  a[1] = 2.0f;  a[2] = 3.0f;  a[3] = 4.0f;
    b[0] = 10.0f; b[1] = 20.0f; b[2] = 30.0f; b[3] = 40.0f;
    r[0] = r[1] = r[2] = r[3] = 0.0f;

    __try {
        _asm {
            lea eax, a
            lea ecx, b
            lea edx, r
            _emit 0x0F           ; movups xmm0, [eax]
            _emit 0x10
            _emit 0x00
            _emit 0x0F           ; movups xmm1, [ecx]
            _emit 0x10
            _emit 0x09
            _emit 0x0F           ; addps xmm0, xmm1
            _emit 0x58
            _emit 0xC1
            _emit 0x0F           ; movups [edx], xmm0
            _emit 0x11
            _emit 0x02
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return R_FAULTED;
    }

    if (r[0] == 11.0f && r[1] == 22.0f && r[2] == 33.0f && r[3] == 44.0f)
        return R_OK;
    return R_WRONG;
}

/*
 * SSE2: r = a addpd b, on two packed doubles (66 0F prefix selects double).
 * Faults on a CPU without SSE2, or on stock 3.51 with OSFXSR clear.
 */
static int
TestSse2(void)
{
    double a[2], b[2], r[2];

    a[0] = 1;  a[1] = 2;
    b[0] = 10; b[1] = 20;
    r[0] = r[1] = 0;

    __try {
        _asm {
            lea eax, a
            lea ecx, b
            lea edx, r
            _emit 0x66           ; movupd xmm0, [eax]
            _emit 0x0F
            _emit 0x10
            _emit 0x00
            _emit 0x66           ; movupd xmm1, [ecx]
            _emit 0x0F
            _emit 0x10
            _emit 0x09
            _emit 0x66           ; addpd xmm0, xmm1
            _emit 0x0F
            _emit 0x58
            _emit 0xC1
            _emit 0x66           ; movupd [edx], xmm0
            _emit 0x0F
            _emit 0x11
            _emit 0x02
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return R_FAULTED;
    }

    if (r[0] == 11.0 && r[1] == 22.0)
        return R_OK;
    return R_WRONG;
}

/*
 * ---------------------------------------------------------------------------
 * Concurrency test: do XMM registers survive context switches?
 *
 * Enabling SSE (CR4.OSFXSR) makes SSE instructions *execute*, but that alone
 * does not make them *correct* when more than one thread uses them: unless the
 * OS saves and restores XMM per thread, one thread's registers get clobbered by
 * another's. That is what the driver's #NM handler and SwapContext detour fix.
 *
 * This test starts several threads, each of which loads a distinct value into
 * XMM0-7, then repeatedly yields and re-checks that its own values are still
 * there. If per-thread XMM state is not preserved, a thread eventually sees
 * another thread's values and reports corruption.
 *
 * With SSE enabled but no state tracking, this should FAIL (that is the unsafe
 * configuration). With the full driver loaded, it should PASS.
 * ---------------------------------------------------------------------------
 */

#define CONC_THREADS  4
#define CONC_SPIN     30000000   /* spin iterations per thread */

static volatile long g_Corrupt = 0;      /* threads that saw bad XMM state */
static volatile long g_Faulted = 0;      /* threads that faulted           */
static volatile long g_Ready   = 0;      /* threads that finished          */

/*
 * Fill XMM0-7 with 32 copies of 'seed' (one per dword lane), then loop:
 * yield, read XMM back, and verify every lane still holds 'seed'.
 */
static DWORD WINAPI
ConcThread(LPVOID param)
{
    unsigned int seed = (unsigned int)(DWORD)param;
    unsigned int pattern[32];            /* 8 regs * 4 dwords            */
    unsigned int readback[32];
    int i;
    int bad = 0;

    for (i = 0; i < 32; i++) {
        pattern[i] = seed;
        readback[i] = 0;
    }

    /*
     * CRITICAL: everything from loading XMM to reading it back must happen in
     * ONE asm block with no C code, CRT call, or Win32 call in between.
     *
     * Modern CRT/KERNEL32 routines (and the compiler itself) use SSE
     * internally, so calling out - even Sleep(0) or printf - destroys XMM and
     * would look exactly like cross-thread corruption. Verified: XMM0 reads
     * back as zero after a plain printf on a modern host.
     *
     * So we spin in place instead of yielding politely. The thread is still
     * preempted by the scheduler (that is the whole point), but nothing in
     * OUR path touches XMM between the load and the check.
     */
    __try {
        _asm {
            lea  eax, pattern
            _emit 0x0F
            _emit 0x10
            _emit 0x00               ; movups xmm0, [eax]
            _emit 0x0F
            _emit 0x10
            _emit 0x48
            _emit 0x10               ; movups xmm1, [eax+0x10]
            _emit 0x0F
            _emit 0x10
            _emit 0x50
            _emit 0x20               ; movups xmm2, [eax+0x20]
            _emit 0x0F
            _emit 0x10
            _emit 0x58
            _emit 0x30               ; movups xmm3, [eax+0x30]
            _emit 0x0F
            _emit 0x10
            _emit 0x60
            _emit 0x40               ; movups xmm4, [eax+0x40]
            _emit 0x0F
            _emit 0x10
            _emit 0x68
            _emit 0x50               ; movups xmm5, [eax+0x50]
            _emit 0x0F
            _emit 0x10
            _emit 0x70
            _emit 0x60               ; movups xmm6, [eax+0x60]
            _emit 0x0F
            _emit 0x10
            _emit 0x78
            _emit 0x70               ; movups xmm7, [eax+0x70]

            /* Spin long enough to be preempted many times over. */
            mov  ecx, CONC_SPIN
        spin_loop:
            dec  ecx
            jnz  spin_loop

            lea  eax, readback
            _emit 0x0F
            _emit 0x11
            _emit 0x00               ; movups [eax], xmm0
            _emit 0x0F
            _emit 0x11
            _emit 0x48
            _emit 0x10               ; movups [eax+0x10], xmm1
            _emit 0x0F
            _emit 0x11
            _emit 0x50
            _emit 0x20               ; movups [eax+0x20], xmm2
            _emit 0x0F
            _emit 0x11
            _emit 0x58
            _emit 0x30               ; movups [eax+0x30], xmm3
            _emit 0x0F
            _emit 0x11
            _emit 0x60
            _emit 0x40               ; movups [eax+0x40], xmm4
            _emit 0x0F
            _emit 0x11
            _emit 0x68
            _emit 0x50               ; movups [eax+0x50], xmm5
            _emit 0x0F
            _emit 0x11
            _emit 0x70
            _emit 0x60               ; movups [eax+0x60], xmm6
            _emit 0x0F
            _emit 0x11
            _emit 0x78
            _emit 0x70               ; movups [eax+0x70], xmm7
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement((LPLONG)&g_Faulted);
        InterlockedIncrement((LPLONG)&g_Ready);
        return 1;
    }

    for (i = 0; i < 32; i++) {
        if (readback[i] != seed) {
            bad = 1;
            break;
        }
    }

    if (bad) {
        InterlockedIncrement((LPLONG)&g_Corrupt);
    }
    InterlockedIncrement((LPLONG)&g_Ready);
    return 0;
}

/*
 * Returns: R_OK if every thread kept its own XMM state, R_WRONG if any thread
 * saw corruption, R_FAULTED if the threads could not run SSE at all.
 */
static int
TestConcurrency(void)
{
    HANDLE h[CONC_THREADS];
    DWORD  id;
    int    i;
    int    started = 0;

    g_Corrupt = 0;
    g_Faulted = 0;
    g_Ready   = 0;

    for (i = 0; i < CONC_THREADS; i++) {
        h[i] = CreateThread(NULL, 0, ConcThread,
                            (LPVOID)(DWORD)(0x11111111 * (unsigned int)(i + 1)),
                            0, &id);
        if (h[i] != NULL) {
            started++;
        }
    }

    if (started == 0) {
        return R_FAULTED;
    }

    for (i = 0; i < CONC_THREADS; i++) {
        if (h[i] != NULL) {
            WaitForSingleObject(h[i], INFINITE);
            CloseHandle(h[i]);
        }
    }

    if (g_Faulted == started) {
        return R_FAULTED;
    }
    if (g_Corrupt > 0) {
        return R_WRONG;
    }
    return R_OK;
}

static const char *
Verdict(int r)
{
    switch (r) {
        case R_OK:      return "WORKING";
        case R_WRONG:   return "ran but WRONG RESULT";
        default:        return "FAULTED (not enabled)";
    }
}

int
main(void)
{
    unsigned int regs[4];
    unsigned int features = 0;
    char vendor[13];
    int mmx, sse, sse2, conc;
    int cpuMmx, cpuFxsr, cpuSse, cpuSse2;

    printf("\n");
    printf("SSE / SSE2 / MMX execution test for Windows NT 3.51\n");
    printf("===================================================\n\n");

    if (!HasCpuid()) {
        printf("This CPU has no CPUID instruction (386/early 486).\n");
        printf("None of MMX/SSE/SSE2 can be present. Nothing to test.\n");
        return 1;
    }

    /* Vendor string: leaf 0 returns it in EBX, EDX, ECX order. */
    DoCpuid(0, regs);
    ((unsigned int *)vendor)[0] = regs[1];
    ((unsigned int *)vendor)[1] = regs[3];
    ((unsigned int *)vendor)[2] = regs[2];
    vendor[12] = '\0';

    DoCpuid(1, regs);
    features = regs[3];

    cpuMmx  = (features & FEAT_MMX)  ? 1 : 0;
    cpuFxsr = (features & FEAT_FXSR) ? 1 : 0;
    cpuSse  = (features & FEAT_SSE)  ? 1 : 0;
    cpuSse2 = (features & FEAT_SSE2) ? 1 : 0;

    printf("CPU vendor        : %s\n", vendor);
    printf("CPUID.1 EDX       : %08X\n", features);
    printf("CPU supports MMX  : %s\n", cpuMmx  ? "yes" : "no");
    printf("CPU supports FXSR : %s\n", cpuFxsr ? "yes" : "no");
    printf("CPU supports SSE  : %s\n", cpuSse  ? "yes" : "no");
    printf("CPU supports SSE2 : %s\n", cpuSse2 ? "yes" : "no");
    printf("\n");

    printf("Executing instructions (faults are caught):\n");

    mmx = TestMmx();
    printf("  MMX   paddd : %s\n", Verdict(mmx));

    sse = TestSse();
    printf("  SSE   addps : %s\n", Verdict(sse));

    sse2 = TestSse2();
    printf("  SSE2  addpd : %s\n", Verdict(sse2));

    /*
     * Only worth running the concurrency test if SSE executes at all; if it
     * faults, every thread would just fault too and tell us nothing new.
     */
    conc = R_FAULTED;
    if (sse == R_OK) {
        printf("\n");
        printf("Concurrency (%d threads, XMM held across context switches):\n",
               CONC_THREADS);
        conc = TestConcurrency();
        if (conc == R_OK) {
            printf("  per-thread XMM : PRESERVED\n");
        } else if (conc == R_WRONG) {
            printf("  per-thread XMM : CORRUPTED (%ld of %d threads)\n",
                   g_Corrupt, CONC_THREADS);
        } else {
            printf("  per-thread XMM : could not run\n");
        }
    }

    printf("\n");
    printf("Interpretation:\n");

    if (cpuSse && sse == R_FAULTED) {
        printf("  * The CPU supports SSE but executing it FAULTS. That means\n");
        printf("    the OS has not set CR4.OSFXSR. This is the expected result\n");
        printf("    on stock NT 3.51 - it is the problem this project fixes.\n");
    } else if (cpuSse && sse == R_OK) {
        printf("  * SSE is enabled and working. If you just loaded the driver,\n");
        printf("    that is the win: NT 3.51 is now running SSE code.\n");
    } else if (!cpuSse) {
        printf("  * This CPU does not report SSE support, so there is nothing\n");
        printf("    for the OS to enable.\n");
    }

    if (cpuMmx && mmx == R_OK) {
        printf("  * MMX already works, as expected - it needs no OSFXSR.\n");
    }

    if (cpuSse2 && sse2 == R_OK && sse == R_OK) {
        printf("  * SSE2 is working too.\n");
    }

    if (sse == R_OK && conc == R_OK) {
        printf("  * XMM state survives context switches, so several threads can\n");
        printf("    use SSE at once. That needs the driver's #NM handler and\n");
        printf("    SwapContext hook, not just OSFXSR.\n");
    } else if (sse == R_OK && conc == R_WRONG) {
        printf("  * XMM state is NOT preserved across threads: SSE executes, but\n");
        printf("    threads clobber each other's registers. That is the expected\n");
        printf("    result with OSFXSR enabled but no per-thread save/restore -\n");
        printf("    single-threaded SSE is fine, concurrent SSE is not safe yet.\n");
    }

    printf("\n");

    /*
     * Exit code: 0 if SSE works and per-thread state is preserved, 3 if SSE
     * works but concurrency is unsafe, 2 if SSE faulted, 1 on odd states.
     */
    if (sse == R_OK && conc == R_OK)    return 0;
    if (sse == R_OK && conc == R_WRONG) return 3;
    if (sse == R_OK)                    return 0;
    if (sse == R_FAULTED)               return 2;
    return 1;
}
