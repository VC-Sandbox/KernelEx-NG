/*
 * mem_ext.c - KernelEx-NG: Windows 98's memory and process-access calls with NT's limits, and traced.
 *
 * 2026-11-01: Chromium blue-screened Windows 98 ("fatal exception 0D at 0028:BFF713DB" = KERNEL32's VxDCall gate)
 * right after chrome.dll started. Windows 98's KERNEL32 checks protection and allocation flags itself, but it
 * accepts addresses up to 0xBFFFFFFF (VirtualAlloc/VirtualProtect: `cmp esi,0BFFFFFFFh`) - i.e. the shared
 * arena, where KERNEL32/USER/GDI and every process's shared memory live - and leaves queries/reads of the
 * system arena (0xC0000000+, VMM and VxDs) to the VMM. NT refuses all of this for user mode. Here:
 *   VirtualQuery(Ex) at >= 0xC0000000            -> 0, ERROR_INVALID_PARAMETER (NT: past user space)
 *        (crashpad and Chromium's memory tools walk the whole address space until VirtualQuery says 0)
 *   ReadProcessMemory at >= 0xC0000000            -> FALSE, ERROR_PARTIAL_COPY
 *   WriteProcessMemory at >= 0x80000000           -> FALSE, ERROR_NOACCESS
 *   VirtualAlloc/VirtualFree with an explicit address in 0x80000000+ -> ERROR_INVALID_ADDRESS
 *   VirtualProtect on a Windows DLL in the shared arena -> ERROR_INVALID_ADDRESS (views stay allowed: Win98
 *        maps file views there and Chromium sizes/protects its shared memory)
 *   protection flags NT has and 98 rejects: PAGE_TARGETS_* / PAGE_REVERT_TO_FILE_MAP (CFG) and PAGE_GUARD are
 *        dropped, PAGE_WRITECOPY/PAGE_EXECUTE_WRITECOPY become READWRITE/EXECUTE_READWRITE
 *   MEM_RESET / MEM_RESET_UNDO ("contents no longer needed" hints, NT only) -> success, nothing changes
 * The address limits apply only in NT 6+ programs (kex_peb_active): Win9x programs keep Windows 98's rules
 * (VA_SHARED memory lives in the shared arena). The flag translations apply to everyone - Windows 98 would
 * only have rejected those calls. Everything else goes to Windows unchanged. In NT 6+ processes (crash log armed) every call is written to
 * KEXTRACE.LOG (budget 8000 lines per process) so a blue screen leaves the last call on disk.
 */
#include "kexnt_common.h"

void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
BOOL kex_bigsec_owns(LPCVOID a, SIZE_T n);                          /* veh_ext.c */
BOOL kex_laa_owns(LPCVOID a, SIZE_T n);
BOOL kex_shm_in_view(LPCVOID a, SIZE_T n);                         /* shm_ext.c (build 138) */            /* laa_ext.c (build 123): blocks above 2 GB of this process */
BOOL kex_laa_is_base(LPCVOID a);
LPVOID kex_laa_lend(SIZE_T n, DWORD type, DWORD prot);
LPVOID kex_laa_lend_at(LPVOID a, SIZE_T n, DWORD type, DWORD prot);
BOOL kex_laa_release(LPVOID a);
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
void kex_laa_seen_reserve(void);
BOOL kex_bigsec_protect(LPVOID a, SIZE_T n, DWORD prot, PDWORD old);
BOOL kex_peb_active(void);           /* peb_ext.c: TRUE in NT 6+ programs (the address limits apply only there:
                                        Win9x programs may use VA_SHARED memory in the shared arena) */

#define SYS_ARENA     0xC0000000UL
#define SHARED_ARENA  0x80000000UL
#define K_MEM_RESET       0x00080000
#define K_MEM_RESET_UNDO  0x01000000
#define K_MEM_LARGE_PAGES 0x20000000

static DWORD fix_protect(DWORD p)
{
    p &= ~(0x40000000UL | 0x80000000UL | PAGE_GUARD | 0x400 /* PAGE_WRITECOMBINE */);
    if ((p & 0xFF) == PAGE_WRITECOPY) p = (p & ~0xFFUL) | PAGE_READWRITE;
    if ((p & 0xFF) == PAGE_EXECUTE_WRITECOPY) p = (p & ~0xFFUL) | PAGE_EXECUTE_READWRITE;
    return p;
}

/* a Windows (or any) DLL image in the shared arena: allocation base carries an MZ header */
static BOOL shared_image(LPCVOID a)
{
    MEMORY_BASIC_INFORMATION m;
    if ((ULONG_PTR)a < SHARED_ARENA || (ULONG_PTR)a >= SYS_ARENA) return FALSE;
    if (!VirtualQuery(a, &m, sizeof(m)) || !m.AllocationBase) return FALSE;
    return !IsBadReadPtr(m.AllocationBase, 2) && *(WORD *)m.AllocationBase == IMAGE_DOS_SIGNATURE;
}

/* routine memory calls: only the first ones are traced (16000 VirtualProtect lines filled Mypal's log, 2026-11-02);
 * refusals and failures are always traced */
static LONG g_mem_traces;
#define MEM_TRACE(w, a, b, c, d) do { if (InterlockedIncrement(&g_mem_traces) <= 2000) kex_trace(w, a, b, c, d); } while (0)

SIZE_T KEXAPI kex_VirtualQuery(LPCVOID a, PMEMORY_BASIC_INFORMATION m, SIZE_T n);

/* build 121: who holds the address space. Discord's renderer (build 120) ended with 1117 MB reserved but not
 * committed - 496 regions of 2 MB holding 149 MB - and 250 MB free; its frames stopped when it ran out. Every
 * reservation of 1 MB or more made by an NT 6+ program is kept with the two callers above Chromium's
 * VirtualAlloc wrapper, and the first time an allocation fails the live ones are summed by caller. */
typedef struct { DWORD base, size, c1, c2; } KRES;
#define NRES 4096
static KRES g_res[NRES];
static volatile LONG g_res_lock;
static LONG g_res_made, g_res_released, g_res_full;
static void res_callers(DWORD ebp, DWORD *c1, DWORD *c2)
{
    DWORD f1;
    *c1 = *c2 = 0;
    if (ebp < 0x10000 || IsBadReadPtr((void *)ebp, 8)) return;
    f1 = ((DWORD *)ebp)[0];                                 /* frame of whoever called kex_VirtualAlloc */
    if (f1 <= ebp || IsBadReadPtr((void *)f1, 8)) return;
    *c1 = ((DWORD *)f1)[1];
    {   DWORD f2 = ((DWORD *)f1)[0];
        if (f2 > f1 && !IsBadReadPtr((void *)f2, 8)) *c2 = ((DWORD *)f2)[1]; }
}
static void res_add(DWORD base, DWORD size, DWORD ebp)
{
    int i; DWORD c1, c2;
    res_callers(ebp, &c1, &c2);
    kex_spin_acquire(&g_res_lock);
    for (i = 0; i < NRES; i++) if (!g_res[i].base) { g_res[i].base = base; g_res[i].size = size; g_res[i].c1 = c1; g_res[i].c2 = c2; break; }
    if (i == NRES) g_res_full++;
    g_res_made++;
    InterlockedExchange(&g_res_lock, 0);
}
static void res_del(DWORD base)
{
    int i;
    kex_spin_acquire(&g_res_lock);
    for (i = 0; i < NRES; i++) if (g_res[i].base == base) { g_res[i].base = 0; g_res_released++; break; }
    InterlockedExchange(&g_res_lock, 0);
}
static void res_where(DWORD a, char *out, DWORD *off)
{
    MEMORY_BASIC_INFORMATION mi; char f[MAX_PATH]; int k, sl = -1;
    lstrcpyA(out, "?"); *off = a;
    if (a && VirtualQuery((LPCVOID)(ULONG_PTR)a, &mi, sizeof(mi)) && mi.AllocationBase &&
        GetModuleFileNameA((HMODULE)mi.AllocationBase, f, MAX_PATH)) {
        for (k = 0; f[k]; k++) if (f[k] == '\\') sl = k;
        lstrcpynA(out, f + sl + 1, 24); *off = a - (DWORD)(ULONG_PTR)mi.AllocationBase;
    }
}
static void res_report(void)
{
    typedef struct { DWORD c1, c2, n, bytes, committed; } AGG;
    static AGG agg[48]; int na = 0, i, j, shown; DWORD total = 0, totc = 0;
    void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
    kex_spin_acquire(&g_res_lock);
    for (i = 0; i < NRES; i++) {
        DWORD c = 0, at; MEMORY_BASIC_INFORMATION m;
        if (!g_res[i].base) continue;
        for (at = g_res[i].base; at < g_res[i].base + g_res[i].size; ) {      /* committed part of it */
            if (!VirtualQuery((LPCVOID)(ULONG_PTR)at, &m, sizeof(m)) || !m.RegionSize) break;
            if (m.State == MEM_COMMIT) c += (DWORD)m.RegionSize;
            at = (DWORD)(ULONG_PTR)m.BaseAddress + (DWORD)m.RegionSize;
        }
        total += g_res[i].size; totc += c;
        for (j = 0; j < na; j++) if (agg[j].c1 == g_res[i].c1 && agg[j].c2 == g_res[i].c2) break;
        if (j == na) { if (na == 48) j = 47; else { na++; agg[j].c1 = g_res[i].c1; agg[j].c2 = g_res[i].c2; agg[j].n = agg[j].bytes = agg[j].committed = 0; } }
        agg[j].n++; agg[j].bytes += g_res[i].size; agg[j].committed += c;
    }
    InterlockedExchange(&g_res_lock, 0);
    kex_crashnote("  RESERVATIONS of 1 MB+ live now (count made, released, KB reserved, KB committed in them)",
                  (DWORD)g_res_made, (DWORD)g_res_released, total >> 10, totc >> 10);
    for (shown = 0; shown < 12; shown++) {                                  /* biggest callers first */
        int best = -1; char t[200], m1[32], m2[32]; DWORD o1, o2;
        for (j = 0; j < na; j++) if (agg[j].n && (best < 0 || agg[j].bytes > agg[best].bytes)) best = j;
        if (best < 0) break;
        res_where(agg[best].c1, m1, &o1); res_where(agg[best].c2, m2, &o2);
        lstrcpyA(t, "    by "); lstrcatA(t, m1); lstrcatA(t, " / "); lstrcatA(t, m2);
        lstrcatA(t, " (count, KB reserved, KB committed, caller offset)");
        kex_crashnote(t, agg[best].n, agg[best].bytes >> 10, agg[best].committed >> 10, o1);
        kex_crashnote("      caller's caller offset", o2, 0, 0, 0);
        agg[best].n = 0;
    }
    if (g_res_full) kex_crashnote("    (reservations not kept: table full)", (DWORD)g_res_full, 0, 0, 0);
}

/* build 122: MEM_RESET / DiscardVirtualMemory really give the pages back. NT drops "contents no longer needed" pages
 * without writing them to the page file; build 121 and earlier only answered success, so Windows 98 kept every such
 * page and, under pressure, WROTE it to the swap file (Discord run, build 121: 2300 page-outs and 11000 page-ins a
 * second, 1 GB machine, frames every 5 s). For the program's own private memory (below 2 GB, not an image, not a
 * view) the whole pages inside the range are decommitted and committed again at once: same address, same
 * protection, still committed, contents zero - which NT allows ("contents undefined"). Partial pages at the ends
 * are left alone. Shared-arena views keep the old answer (no change). Returns the bytes given back. */
static volatile LONG g_disc_mb, g_disc_fail;
DWORD kex_discard_private(LPVOID addr, SIZE_T n)
{
    DWORD a = ((DWORD)(ULONG_PTR)addr + 0xFFF) & ~0xFFFUL, end = ((DWORD)(ULONG_PTR)addr + (DWORD)n) & ~0xFFFUL, done = 0;
    static volatile LONG bytes_acc;
    if (!addr || end <= a || !kex_peb_active()) return 0;
    if (end > SHARED_ARENA && !kex_laa_owns((LPCVOID)(ULONG_PTR)a, end - a)) return 0;   /* build 123: own blocks above 2 GB too */
    while (a < end) {
        MEMORY_BASIC_INFORMATION m; DWORD rend, len, prot;
        if (!VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) || !m.RegionSize) break;
        rend = (DWORD)(ULONG_PTR)m.BaseAddress + (DWORD)m.RegionSize; if (rend > end) rend = end;
        len = rend - a; prot = m.Protect;
        if (m.State == MEM_COMMIT && (m.Type == MEM_PRIVATE || a >= SHARED_ARENA) && !(prot & (PAGE_GUARD | PAGE_NOACCESS)) && (prot & 0xFF) &&
            !kex_bigsec_owns((LPCVOID)(ULONG_PTR)a, len)) {
            if (VirtualFree((LPVOID)(ULONG_PTR)a, len, MEM_DECOMMIT)) {
                int k;
                for (k = 0; k < 50 && !VirtualAlloc((LPVOID)(ULONG_PTR)a, len, MEM_COMMIT, prot); k++) Sleep(10);
                if (k == 50) {      /* could not take the commit back: say so loudly (the range is now reserved only) */
                    void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
                    if (InterlockedIncrement(&g_disc_fail) <= 10)
                        kex_crashnote("DISCARD: pages decommitted but could not be committed again (address, bytes, protection, error)", a, len, prot, GetLastError());
                } else done += len;
            }
        }
        a = rend;
    }
    if (done) {
        LONG t = InterlockedExchangeAdd(&bytes_acc, (LONG)done) + (LONG)done;
        while (t >= (1L << 20)) {                 /* whole MB counted, notes at 64, 256, 1024, 4096 MB */
            LONG mb;
            if (InterlockedCompareExchange(&bytes_acc, t - (1L << 20), t) != t) { t = bytes_acc; continue; }
            mb = InterlockedIncrement(&g_disc_mb);
            if (mb == 64 || mb == 256 || mb == 1024 || mb == 4096) {
                void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
                kex_crashnote("DISCARD: memory the program no longer needed given back instead of swapped (MB so far)", (DWORD)mb, 0, 0, 0);
            }
            t -= (1L << 20);
        }
    }
    return done;
}
DWORD kex_discard_mb(void) { return (DWORD)g_disc_mb; }

LPVOID KEXAPI kex_VirtualAlloc(LPVOID a, SIZE_T n, DWORD type, DWORD prot)
{
    LPVOID r; DWORD p = fix_protect(prot);
    MEM_TRACE("VirtualAlloc", (DWORD)(ULONG_PTR)a, (DWORD)n, type, prot);
    /* MEM_RESET / MEM_RESET_UNDO are hints that change nothing, so they are answered before the arena rule:
     * Chromium resets pages of shared-memory views, which live in the 9x shared arena
     * (discardable_shared_memory.cc:468 CHECKs the result, build 19). kex_VirtualQuery knows KEXALIAS views. */
    if (type & (K_MEM_RESET | K_MEM_RESET_UNDO)) {
        MEMORY_BASIC_INFORMATION m;
        if (!a || !kex_VirtualQuery(a, &m, sizeof(m)) || m.State != MEM_COMMIT) {
            kex_trace("  MEM_RESET refused: not committed", (DWORD)(ULONG_PTR)a, (DWORD)n, 0, 0);
            SetLastError(ERROR_INVALID_ADDRESS); return NULL;
        }
        if ((((ULONG_PTR)a < SHARED_ARENA && m.Type == MEM_PRIVATE) || kex_laa_owns(a, n)) && kex_peb_active()) {   /* build 122/123 */
            if (type & K_MEM_RESET_UNDO) {          /* NT: failure = "some of it was replaced by zeros" */
                SetLastError(ERROR_INVALID_ADDRESS); return NULL;
            }
            kex_discard_private(a, n);
        }
        return a;
    }
    if (kex_peb_active() && a && !(type & 0x08000000) && ((ULONG_PTR)a >= SHARED_ARENA || (ULONG_PTR)a + n > SHARED_ARENA) &&
        !kex_laa_owns(a, n) &&
        /* build 138: committing pages of the program's own file-mapping view stays allowed. On NT that view is ordinary
         * user memory; Windows 98 maps every pagefile view into the shared arena. WPF's font cache creates a
         * SEC_RESERVE section and commits it page by page; the refusal made FileMapping.Commit throw
         * OutOfMemoryException (probe dotnet/fmap.cs, crash notes "VirtualAlloc refused in the shared arena") */
        !((type & MEM_COMMIT) && !(type & MEM_RESERVE) && kex_shm_in_view(a, n))) {                      /* build 123: inside its own blocks above 2 GB it may commit etc. */
        if (type & MEM_RESERVE) {                   /* build 123: allocator retrying at an aligned address up there */
            LPVOID r2 = kex_laa_lend_at(a, n, type & ~(DWORD)K_MEM_LARGE_PAGES, p);
            if (r2) return r2;
        }
        kex_trace("  refused: shared/system arena", 0, 0, 0, 0);
        {   static LONG nr; void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
            if (InterlockedIncrement(&nr) <= 10) kex_crashnote("VirtualAlloc refused in the shared arena (address, size, type, in own view)",
                                                              (DWORD)(ULONG_PTR)a, (DWORD)n, type, kex_shm_in_view(a, n)); }
        SetLastError(ERROR_INVALID_ADDRESS); return NULL;
    }
    type &= ~(DWORD)K_MEM_LARGE_PAGES;
    r = VirtualAlloc(a, n, type, p);
    if (r && (type & MEM_RESERVE) && n >= 0x100000 && kex_peb_active()) {   /* build 121 */
        res_add((DWORD)(ULONG_PTR)r, (DWORD)n, (DWORD)(ULONG_PTR)__builtin_frame_address(0));
        kex_laa_seen_reserve();                     /* build 123: one sweep + the sweeper thread, once per process */
    }
    if (r) MEM_TRACE("  ->", (DWORD)(ULONG_PTR)r, 0, p, 0);
    else {
        DWORD le = GetLastError(); MEMORY_BASIC_INFORMATION q;
        kex_trace("VirtualAlloc failed", (DWORD)(ULONG_PTR)a, (DWORD)n, le, p);
        /* build 132: committing (part of) the calling thread's own stack. The .NET 4 runtime commits a thread's whole
         * stack up front, as NT allows (measured: CLR.DLL+c96fe VirtualAlloc(01391000, 106000h, MEM_COMMIT) -> error 8,
         * HELLO.EXE then exited with 0x800703E9 = ERROR_STACK_OVERFLOW). Windows 98 refuses MEM_COMMIT on a thread-stack
         * region and commits stack pages itself as the stack grows (guard page). The range is reported committed:
         * the program's guarantee becomes Windows 98's on-demand growth. Only the caller's own stack reservation. */
        if (a && (type & MEM_COMMIT) && !(type & MEM_RESERVE) && le == ERROR_NOT_ENOUGH_MEMORY) {
            MEMORY_BASIC_INFORMATION s1, s2; LPCVOID me = __builtin_frame_address(0);
            if (VirtualQuery(a, &s1, sizeof(s1)) && VirtualQuery(me, &s2, sizeof(s2)) && s1.AllocationBase && s1.AllocationBase == s2.AllocationBase &&
                (BYTE *)a + n <= (BYTE *)s2.AllocationBase + 0x4000000) {
                static LONG ns; void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
                if (InterlockedIncrement(&ns) <= 10) kex_crashnote("VirtualAlloc MEM_COMMIT of the thread's own stack: left to Windows 98's on-demand stack growth (address, size, stack base, -)",
                                                                  (DWORD)(ULONG_PTR)a, (DWORD)n, (DWORD)(ULONG_PTR)s2.AllocationBase, 0);
                SetLastError(ERROR_SUCCESS);
                return a;
            }
        }
        if ((type & MEM_COMMIT) && !(type & MEM_RESERVE)) {   /* build 138: every refused commit, with the page state */
            static LONG nl; void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
            MEMORY_BASIC_INFORMATION m0; ZeroMemory(&m0, sizeof(m0)); if (a) VirtualQuery(a, &m0, sizeof(m0));
            if (InterlockedIncrement(&nl) <= 20) kex_crashnote("VirtualAlloc MEM_COMMIT refused (address, size, error, state|type>>8)",
                                                              (DWORD)(ULONG_PTR)a, (DWORD)n, le, m0.State | (m0.Type >> 8));
        }
        /* build 61: a reservation at an address that is already taken - NT says ERROR_INVALID_ADDRESS (487),
         * Windows 98 says ERROR_NOT_ENOUGH_MEMORY (8), which reads like a real out-of-memory. PartitionAlloc
         * tries a hinted address first for every 2 MB super page (build 60: 30 such notes, all harmless). */
        if (a && (type & MEM_RESERVE) && le == ERROR_NOT_ENOUGH_MEMORY &&
            (!VirtualQuery(a, &q, sizeof(q)) || q.State != MEM_FREE || q.RegionSize < n)) {
            SetLastError(ERROR_INVALID_ADDRESS);
            return NULL;
        }
        if (!a && (type & MEM_RESERVE) && le == ERROR_NOT_ENOUGH_MEMORY && kex_peb_active()) {
            /* build 123: a large address aware program's 2 GB are full - above 2 GB, as 64-bit Windows would give it */
            LPVOID r2 = kex_laa_lend(n, type, p);
            if (r2) { SetLastError(0); return r2; }
            SetLastError(le);
        }
        {   /* build 60: "Array buffer allocation failed" in Chrome - address space or memory? the crash log says */
            static LONG nf; void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
            if (kex_peb_active() && InterlockedIncrement(&nf) <= 30) {
                DWORD free_total = 0, free_max = 0, at = 0x10000; MEMORY_BASIC_INFORMATION m;
                while (at < SHARED_ARENA && VirtualQuery((LPCVOID)(ULONG_PTR)at, &m, sizeof(m)) >= sizeof(m) && m.RegionSize) {
                    if (m.State == MEM_FREE) { free_total += (DWORD)m.RegionSize; if (m.RegionSize > free_max) free_max = (DWORD)m.RegionSize; }
                    at = (DWORD)(ULONG_PTR)m.BaseAddress + (DWORD)m.RegionSize;
                }
                kex_crashnote("VirtualAlloc FAILED (size, type, error, address asked)", (DWORD)n, type, le, (DWORD)(ULONG_PTR)a);
                {   /* build 117: who asked (Discord renderer: 16 x 1 GB, then 11 x 772 MB - which code?) */
                    DWORD ra = (DWORD)(ULONG_PTR)__builtin_return_address(0); char f[MAX_PATH], t[128]; int k, sl = -1;
                    MEMORY_BASIC_INFORMATION mi; t[0] = 0;
                    if (VirtualQuery((LPCVOID)(ULONG_PTR)ra, &mi, sizeof(mi)) && mi.AllocationBase &&
                        GetModuleFileNameA((HMODULE)mi.AllocationBase, f, MAX_PATH)) {
                        for (k = 0; f[k]; k++) if (f[k] == '\\') sl = k;
                        lstrcpyA(t, "  asked by (module offset, return address): "); lstrcpynA(t + lstrlenA(t), f + sl + 1, 60);
                        kex_crashnote(t, ra - (DWORD)(ULONG_PTR)mi.AllocationBase, ra, 0, 0);
                    } else kex_crashnote("  asked by (return address, not in a module)", ra, 0, 0, 0);
                }
                kex_crashnote("  address space below 2 GB: free KB total, largest free block KB", free_total >> 10, free_max >> 10, 0, 0);
                if (!a && (free_max < (64u << 20) || n >= (64u << 20))) {   /* build 121: a real shortage, not a taken hint */
                    static LONG once; if (!InterlockedExchange(&once, 1)) res_report(); }
                {   /* build 62: windows93 asks for 1 GB in one piece (largest hole was 512 MB) - who splits the
                     * 2 GB? Once per process, for a failed request of 64 MB or more: every allocation of 4 MB or
                     * more and every hole of 16 MB or more below 2 GB, in address order. */
                    static LONG mapped;
                    if (n >= (64u << 20) && !InterlockedExchange(&mapped, 1)) {
                        DWORD at2 = 0x10000, base = 0, bsize = 0, btype = 0;
                        kex_crashnote("  ADDRESS MAP below 2 GB (start, size KB, kind 0 free / 1 image / 2 mapped / 3 private)", 0, 0, 0, 0);
                        for (;;) {
                            BOOL more = at2 < SHARED_ARENA && VirtualQuery((LPCVOID)(ULONG_PTR)at2, &m, sizeof(m)) >= sizeof(m) && m.RegionSize;
                            DWORD rb = more ? (m.State == MEM_FREE ? (DWORD)(ULONG_PTR)m.BaseAddress : (DWORD)(ULONG_PTR)m.AllocationBase) : 0;
                            if (!more || rb != base) {      /* flush the previous allocation / hole */
                                if (base && ((btype == 0 && bsize >= (16u << 20)) || (btype && bsize >= (4u << 20)))) {
                                    char nm[96]; nm[0] = 0;
                                    if (btype == 1) {
                                        char f[MAX_PATH]; int k, sl = -1;
                                        if (GetModuleFileNameA((HMODULE)(ULONG_PTR)base, f, MAX_PATH)) {
                                            for (k = 0; f[k]; k++) if (f[k] == '\\') sl = k;
                                            lstrcpyA(nm, "    image "); lstrcpynA(nm + 10, f + sl + 1, 80);
                                        } else lstrcpyA(nm, "    image");
                                    } else lstrcpyA(nm, btype == 0 ? "    free" : btype == 2 ? "    mapped" : "    private");
                                    kex_crashnote(nm, base, bsize >> 10, btype, 0);
                                }
                                if (!more) break;
                                base = rb; bsize = 0;
                                btype = m.State == MEM_FREE ? 0 : m.Type == MEM_IMAGE ? 1 : m.Type == MEM_MAPPED ? 2 : 3;
                            }
                            bsize += (DWORD)m.RegionSize;
                            at2 = (DWORD)(ULONG_PTR)m.BaseAddress + (DWORD)m.RegionSize;
                        }
                    }
                }
            }
        }
        SetLastError(le);
    }
    return r;
}

BOOL KEXAPI kex_VirtualFree(LPVOID a, SIZE_T n, DWORD type)
{
    BOOL r;
    MEM_TRACE("VirtualFree", (DWORD)(ULONG_PTR)a, (DWORD)n, type, 0);
    if (kex_peb_active() && (ULONG_PTR)a >= SHARED_ARENA) {
        /* build 123: its own blocks above 2 GB - releasing one goes through the system-wide table */
        if ((type & MEM_RELEASE) && kex_laa_is_base(a)) return kex_laa_release(a);
        if (!(type & MEM_RELEASE) && kex_laa_owns(a, n)) return VirtualFree(a, n, type);
        kex_trace("  refused: shared/system arena", 0, 0, 0, 0);
        if (type & MEM_RELEASE) {   /* build 128: a refused release above 2 GB is a Chrome CHECK - say so */
            static LONG k; if (InterlockedIncrement(&k) <= 20)
                kex_crashnote("VirtualFree(MEM_RELEASE) above 2 GB refused: not one of this process's blocks (address, size, type, -)", (DWORD)(ULONG_PTR)a, (DWORD)n, type, 0);
        }
        SetLastError(ERROR_INVALID_ADDRESS); return FALSE;
    }
    r = VirtualFree(a, n, type);
    if (r && (type & MEM_RELEASE)) res_del((DWORD)(ULONG_PTR)a);          /* build 121 */
    if (!r) kex_trace("  -> FALSE", GetLastError(), 0, 0, 0);
    return r;
}

BOOL KEXAPI kex_VirtualProtect(LPVOID a, SIZE_T n, DWORD prot, PDWORD old)
{
    BOOL r; DWORD p = fix_protect(prot), dummy;
    MEM_TRACE("VirtualProtect", (DWORD)(ULONG_PTR)a, (DWORD)n, prot, 0);
    if (kex_peb_active() && ((ULONG_PTR)a >= SYS_ARENA || (shared_image(a) && !kex_laa_owns(a, n)))) { kex_trace("  refused: system arena / shared DLL", 0, 0, 0, 0); SetLastError(ERROR_INVALID_ADDRESS); return FALSE; }
    if (kex_bigsec_owns(a, n)) return kex_bigsec_protect(a, n, p, old ? old : &dummy);   /* see veh_ext.c */
    r = VirtualProtect(a, n, p, old ? old : &dummy);
    if (!r) kex_trace("  -> FALSE", GetLastError(), 0, 0, 0);
    return r;
}

DWORD kex_bigsec_reported_protect(LPCVOID a);   /* veh_ext.c */

/* build 131: Windows 98's VirtualQuery reports every region as MEM_PRIVATE, also the pages of a loaded module.
 * The Visual C++ runtime's _except_handler3 (VCRUNTIME140 _ValidateEH3RN) accepts a __try scope table only when
 * VirtualQuery says MEM_IMAGE - otherwise it marks the frame invalid and searches on, so EVERY __try/__except
 * built with _except_handler3 is skipped on 98 and the exception becomes unhandled (Pale Moon 35: SetThreadName's
 * RaiseException(406D1388) inside __try in MOZJS.DLL -> "illegal operation"). On Windows 98 a module is one
 * allocation at its base; report MEM_IMAGE when that base holds an MZ/PE header whose SizeOfImage covers the
 * whole allocation as laid out in memory (a plain file view of a PE file is file-sized, not image-sized). */
static BOOL image_alloc(PVOID base, LPCVOID a)
{
    const BYTE *b = (const BYTE *)base; const IMAGE_NT_HEADERS *nt; MEMORY_BASIC_INFORMATION e; DWORD lf, sz;
    if (!b || IsBadReadPtr(b, 0x40) || *(const WORD *)b != IMAGE_DOS_SIGNATURE) return FALSE;
    lf = *(const DWORD *)(b + 0x3c);
    if (lf < 0x40 || lf > 0x1000 || IsBadReadPtr(b + lf, sizeof(IMAGE_NT_HEADERS))) return FALSE;
    nt = (const IMAGE_NT_HEADERS *)(b + lf);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return FALSE;
    sz = nt->OptionalHeader.SizeOfImage;
    if (sz < 0x1000 || (ULONG_PTR)a - (ULONG_PTR)b >= sz) return FALSE;
    if (!VirtualQuery(b + sz - 1, &e, sizeof(e)) || e.AllocationBase != base || e.State == MEM_FREE) return FALSE;
    return TRUE;
}
static void fix_type(LPCVOID a, PMEMORY_BASIC_INFORMATION m, SIZE_T r)
{
    if (r >= sizeof(*m) && m->State != MEM_FREE && m->Type != MEM_IMAGE && image_alloc(m->AllocationBase, a))
        m->Type = MEM_IMAGE;
}

/* build 132: the stack guard page of a .NET thread, as NT reports it. NT keeps a PAGE_GUARD page just below the committed
 * part of a thread's stack; Windows 98 grows a stack without one (the next page below is reserved and committed on
 * touch), so VirtualQuery never shows PAGE_GUARD. Measured: the .NET 2.0 runtime, after every caught exception
 * (ResumeAtJitEH -> Thread::RestoreGuardPage), scans its stack downward for a page with PAGE_GUARD
 * (Thread::MarkPageAsGuard = VirtualQuery + test 0x100); finding none it raised a fatal "stack overflow" (0x800703E9) and
 * waited for a debugger - every try/catch hung the program. In .NET processes, a query of the calling thread's own
 * stack reports the reserved page directly below the committed part - the one Windows 98 commits next - as committed
 * PAGE_READWRITE | PAGE_GUARD, and the rest of that reserved range as before. */
int kex_gate_is_clr(void);
static void stack_guard(LPCVOID a, PMEMORY_BASIC_INFORMATION m)
{
    MEMORY_BASIC_INFORMATION me, up; BYTE *top, *g;
    if (m->State != MEM_RESERVE || !VirtualQuery(&me, &me, sizeof(me)) || me.AllocationBase != m->AllocationBase || !kex_gate_is_clr()) return;
    top = (BYTE *)m->BaseAddress + m->RegionSize;
    if (!VirtualQuery(top, &up, sizeof(up)) || up.State != MEM_COMMIT || up.AllocationBase != m->AllocationBase || m->RegionSize < 0x1000) return;
    g = top - 0x1000;
    if ((const BYTE *)a >= g) {
        m->BaseAddress = g; m->RegionSize = 0x1000; m->State = MEM_COMMIT; m->Protect = PAGE_READWRITE | PAGE_GUARD; m->Type = MEM_PRIVATE;
    } else m->RegionSize -= 0x1000;
}

SIZE_T KEXAPI kex_VirtualQuery(LPCVOID a, PMEMORY_BASIC_INFORMATION m, SIZE_T n)
{
    SIZE_T r; DWORD bp;
    kex_trace("VirtualQuery", (DWORD)(ULONG_PTR)a, (DWORD)n, 0, 0);
    if (kex_peb_active() && (ULONG_PTR)a >= SYS_ARENA) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    { BOOL kex_alias_query(LPCVOID a, PMEMORY_BASIC_INFORMATION m);   /* shm_ext.c: KEXALIAS views */
      if (m && n >= sizeof(*m) && kex_alias_query(a, m)) return sizeof(*m); }
    r = VirtualQuery(a, m, n);
    if (r >= 0x18 && m && m->State == MEM_COMMIT && (bp = kex_bigsec_reported_protect(a)) != 0) {
        m->Protect = bp;                       /* a big-file section page: the section's protection */
        kex_trace("  bigsec reported protect", bp, 0, 0, 0);
    }
    if (m) fix_type(a, m, r);
    if (m && r >= sizeof(*m)) stack_guard(a, m);
    return r;
}

SIZE_T KEXAPI kex_VirtualQueryEx(HANDLE h, LPCVOID a, PMEMORY_BASIC_INFORMATION m, SIZE_T n)
{
    kex_trace("VirtualQueryEx", (DWORD)(ULONG_PTR)h, (DWORD)(ULONG_PTR)a, (DWORD)n, 0);
    if (kex_peb_active() && (ULONG_PTR)a >= SYS_ARENA) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    { SIZE_T r = VirtualQueryEx(h, a, m, n);
      if (m && h == GetCurrentProcess()) fix_type(a, m, r);
      return r; }
}

BOOL KEXAPI kex_ReadProcessMemory(HANDLE h, LPCVOID a, LPVOID buf, SIZE_T n, SIZE_T *done)
{
    kex_trace("ReadProcessMemory", (DWORD)(ULONG_PTR)h, (DWORD)(ULONG_PTR)a, (DWORD)n, 0);
    if (kex_peb_active() && ((ULONG_PTR)a >= SYS_ARENA || (ULONG_PTR)a + n > SYS_ARENA || (ULONG_PTR)a + n < (ULONG_PTR)a)) {
        if (done) *done = 0;
        SetLastError(ERROR_PARTIAL_COPY); return FALSE;
    }
    return ReadProcessMemory(h, a, buf, n, done);
}

/* ---- build 131: VirtualAllocEx / VirtualFreeEx / VirtualProtectEx for ANOTHER process.
 * Windows 98 cannot allocate in or re-protect another process's private memory (KernelEx's VirtualAllocEx starts a
 * thread in the target; for a child still suspended it came back with shared-arena memory anyway, kextest [suspended
 * child]). Chromium's sandbox (Firefox 115 content processes) reserves 64 KB in the child it has just created, commits
 * its interception thunks there, writes them, and re-protects the child's code before patching it. Memory "of another
 * process" is therefore taken from the shared arena (visible to that process; reserve/commit/protect/release work there,
 * probes/lprobe.c, laa_ext.c), recorded with the target's id, and freed once the target has ended (Windows keeps
 * shared-arena memory after its process is gone). WriteProcessMemory may write into such blocks only; VirtualProtectEx of
 * other memory of another process changes nothing on 98 (its WriteProcessMemory ignores page protection) and reports
 * the current protection. */
#define XB_MAX 128
static struct { DWORD base, size, pid; } g_xb[XB_MAX];
static volatile LONG g_xb_lock;
DWORD kex_process_id(HANDLE process);                                    /* chrome_ext.c */
static BOOL pid_ended(DWORD pid)
{
    HANDLE p = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid); DWORD code = STILL_ACTIVE;
    if (!p) return TRUE;
    if (!GetExitCodeProcess(p, &code)) code = 0;
    CloseHandle(p);
    return code != STILL_ACTIVE;
}
static void xb_sweep(void)               /* blocks of processes that have ended (called with no lock held) */
{
    int i;
    for (i = 0; i < XB_MAX; i++) {
        DWORD b, pid;
        kex_spin_acquire(&g_xb_lock); b = g_xb[i].base; pid = g_xb[i].pid; InterlockedExchange(&g_xb_lock, 0);
        if (b && pid_ended(pid)) {
            kex_spin_acquire(&g_xb_lock);
            if (g_xb[i].base == b) { g_xb[i].base = g_xb[i].size = g_xb[i].pid = 0; InterlockedExchange(&g_xb_lock, 0); VirtualFree((LPVOID)(ULONG_PTR)b, 0, MEM_RELEASE); }
            else InterlockedExchange(&g_xb_lock, 0);
        }
    }
}
static BOOL xb_add(DWORD base, DWORD size, DWORD pid)
{
    int i; BOOL ok = FALSE;
    kex_spin_acquire(&g_xb_lock);
    for (i = 0; i < XB_MAX; i++) if (!g_xb[i].base) { g_xb[i].base = base; g_xb[i].size = size; g_xb[i].pid = pid; ok = TRUE; break; }
    InterlockedExchange(&g_xb_lock, 0);
    return ok;
}
static int xb_find(DWORD a, DWORD n, DWORD pid)   /* index of the recorded block of pid holding [a, a+n), or -1 */
{
    int i, r = -1;
    kex_spin_acquire(&g_xb_lock);
    for (i = 0; i < XB_MAX; i++)
        if (g_xb[i].base && g_xb[i].pid == pid && a >= g_xb[i].base && a - g_xb[i].base < g_xb[i].size && n <= g_xb[i].size - (a - g_xb[i].base)) { r = i; break; }
    InterlockedExchange(&g_xb_lock, 0);
    return r;
}
LPVOID KEXAPI kex_VirtualAlloc(LPVOID a, SIZE_T n, DWORD type, DWORD prot);
LPVOID KEXAPI kex_VirtualAllocEx(HANDLE hp, LPVOID a, SIZE_T n, DWORD type, DWORD prot)
{
    DWORD pid = kex_process_id(hp); LPVOID r;
    if (!pid) { SetLastError(ERROR_INVALID_HANDLE); return NULL; }
    if (pid == GetCurrentProcessId()) return kex_VirtualAlloc(a, n, type, prot);
    if (a) {                                                     /* inside a block this process gave the target */
        if (xb_find((DWORD)(ULONG_PTR)a, (DWORD)n, pid) < 0) { SetLastError(ERROR_INVALID_ADDRESS); return NULL; }
        return VirtualAlloc(a, n, type & (MEM_COMMIT | MEM_RESERVE), fix_protect(prot));
    }
    xb_sweep();
    r = VirtualAlloc(NULL, n, (type & (MEM_COMMIT | MEM_RESERVE)) | 0x08000000 /* VA_SHARED */, fix_protect(prot));
    if (!r) return NULL;
    if (!xb_add((DWORD)(ULONG_PTR)r, (DWORD)((n + 0xFFFF) & ~0xFFFFUL), pid)) { VirtualFree(r, 0, MEM_RELEASE); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    kex_trace("VirtualAllocEx: another process's block in the shared arena (address, size, its process)", (DWORD)(ULONG_PTR)r, (DWORD)n, pid, 0);
    return r;
}
BOOL KEXAPI kex_VirtualFree(LPVOID a, SIZE_T n, DWORD type);
BOOL KEXAPI kex_VirtualFreeEx(HANDLE hp, LPVOID a, SIZE_T n, DWORD type)
{
    DWORD pid = kex_process_id(hp); int i;
    if (!pid) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (pid == GetCurrentProcessId()) return kex_VirtualFree(a, n, type);
    if ((i = xb_find((DWORD)(ULONG_PTR)a, (type & MEM_RELEASE) ? 1 : (DWORD)n, pid)) < 0) { SetLastError(ERROR_INVALID_ADDRESS); return FALSE; }
    if (type & MEM_RELEASE) {
        if (g_xb[i].base != (DWORD)(ULONG_PTR)a) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        kex_spin_acquire(&g_xb_lock); g_xb[i].base = g_xb[i].size = g_xb[i].pid = 0; InterlockedExchange(&g_xb_lock, 0);
        return VirtualFree(a, 0, MEM_RELEASE);
    }
    return VirtualFree(a, n, type);
}
BOOL KEXAPI kex_VirtualProtectEx(HANDLE hp, LPVOID a, SIZE_T n, DWORD prot, PDWORD old)
{
    DWORD pid = kex_process_id(hp); MEMORY_BASIC_INFORMATION m; DWORD tmp;
    if (!pid) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (!old) old = &tmp;
    if (pid == GetCurrentProcessId()) return kex_VirtualProtect(a, n, prot, old);
    if (xb_find((DWORD)(ULONG_PTR)a, (DWORD)n, pid) >= 0) return VirtualProtect(a, n, fix_protect(prot), old);
    if (VirtualProtectEx(hp, a, n, fix_protect(prot), old)) return TRUE;
    if (!VirtualQueryEx(hp, a, &m, sizeof(m)) || m.State != MEM_COMMIT) { SetLastError(ERROR_INVALID_ADDRESS); return FALSE; }
    *old = m.Protect;                                               /* unchanged: see above */
    return TRUE;
}

BOOL KEXAPI kex_WriteProcessMemory(HANDLE h, LPVOID a, LPCVOID buf, SIZE_T n, SIZE_T *done)
{
    kex_trace("WriteProcessMemory", (DWORD)(ULONG_PTR)h, (DWORD)(ULONG_PTR)a, (DWORD)n, 0);
    if (kex_peb_active() && ((ULONG_PTR)a >= SHARED_ARENA || (ULONG_PTR)a + n > SHARED_ARENA) &&
        !((ULONG_PTR)a < SYS_ARENA && xb_find((DWORD)(ULONG_PTR)a, (DWORD)n, kex_process_id(h)) >= 0)) {   /* build 131 */
        if (done) *done = 0;
        SetLastError(ERROR_NOACCESS); return FALSE;
    }
    return WriteProcessMemory(h, a, buf, n, done);
}

/* trace only */
BOOL KEXAPI kex_GetThreadContext(HANDLE t, LPCONTEXT c) { kex_trace("GetThreadContext", (DWORD)(ULONG_PTR)t, c ? c->ContextFlags : 0, 0, 0); return GetThreadContext(t, c); }
BOOL KEXAPI kex_SetThreadContext(HANDLE t, const CONTEXT *c) { kex_trace("SetThreadContext", (DWORD)(ULONG_PTR)t, c ? c->ContextFlags : 0, 0, 0); return SetThreadContext(t, c); }
DWORD KEXAPI kex_SuspendThread(HANDLE t) { kex_trace("SuspendThread", (DWORD)(ULONG_PTR)t, 0, 0, 0); return SuspendThread(t); }
DWORD KEXAPI kex_ResumeThread(HANDLE t) { kex_trace("ResumeThread", (DWORD)(ULONG_PTR)t, 0, 0, 0); return ResumeThread(t); }
DWORD kex_pid_real(DWORD id);   /* pid_ext.c */
HANDLE KEXAPI kex_OpenProcess(DWORD acc, BOOL inh, DWORD pid) { HANDLE r; kex_trace("OpenProcess", acc, pid, 0, 0); r = OpenProcess(acc, inh, kex_pid_real(pid)); kex_trace("  ->", (DWORD)(ULONG_PTR)r, r ? 0 : GetLastError(), 0, 0); return r; }
BOOL KEXAPI kex_DeviceIoControl(HANDLE h, DWORD code, LPVOID in, DWORD nin, LPVOID out, DWORD nout, LPDWORD ret, LPOVERLAPPED ov)
{ kex_trace("DeviceIoControl", (DWORD)(ULONG_PTR)h, code, nin, nout); return DeviceIoControl(h, code, in, nin, out, nout, ret, ov); }
BOOL KEXAPI kex_FlushInstructionCache(HANDLE h, LPCVOID a, SIZE_T n) { kex_trace("FlushInstructionCache", (DWORD)(ULONG_PTR)h, (DWORD)(ULONG_PTR)a, (DWORD)n, 0); return FlushInstructionCache(h, a, n); }
DWORD_PTR KEXAPI kex_SetThreadAffinityMask(HANDLE t, DWORD_PTR m) { kex_trace("SetThreadAffinityMask", (DWORD)(ULONG_PTR)t, (DWORD)m, 0, 0); return SetThreadAffinityMask(t, m); }
BOOL KEXAPI kex_VirtualLock(LPVOID a, SIZE_T n) { kex_trace("VirtualLock", (DWORD)(ULONG_PTR)a, (DWORD)n, 0, 0); return VirtualLock(a, n); }
BOOL KEXAPI kex_VirtualUnlock(LPVOID a, SIZE_T n) { kex_trace("VirtualUnlock", (DWORD)(ULONG_PTR)a, (DWORD)n, 0, 0); return VirtualUnlock(a, n); }
LONG kex_view_release(LPCVOID a);   /* shm_ext.c */
BOOL kex_alias_release(LPCVOID a, void **view);   /* shm_ext.c */
BOOL KEXAPI kex_UnmapViewOfFile(LPCVOID a)
{
    LONG left; void *v; BOOL via_alias = FALSE;
    LONG kex_view_release2(LPCVOID a, BOOL via_alias);
    { BOOL kex_fview_unmap(LPCVOID a); if (kex_fview_unmap(a)) return TRUE; }   /* fview_ext.c: a private file view */
    { BOOL kex_imgsec_unmap(LPCVOID a); if (kex_imgsec_unmap(a)) return TRUE; } /* imgsec_ext.c: an image-layout view */
    if (kex_alias_release(a, &v)) {     /* a second view made by KEXALIAS.VXD: gone; now release the real one */
        kex_trace("UnmapViewOfFile (alias)", (DWORD)(ULONG_PTR)a, (DWORD)(ULONG_PTR)v, 0, 0);
        a = v; via_alias = TRUE;
    } else {
        LPCVOID kex_view_from_aligned(LPCVOID a);
        a = kex_view_from_aligned(a);   /* Chromium unmaps AlignDown(view, 64 KB) */
    }
    left = kex_view_release2(a, via_alias);
    kex_trace("UnmapViewOfFile", (DWORD)(ULONG_PTR)a, (DWORD)left, 0, 0);
    if (left > 0) {                     /* another view of this address is still in use (shm_ext.c) */
        int kex_shm_refcounted(void);   /* build 37: Windows 98 counts real maps - give this one back */
        if (kex_shm_refcounted()) { BOOL kex_real_unmap(LPCVOID a); BOOL ok = kex_real_unmap(a); void kex_shm_note_unmap(BOOL ok); kex_shm_note_unmap(ok); }
        return TRUE;
    }
    {
        void kex_shm_note_unmap(BOOL ok);
        BOOL kex_real_unmap(LPCVOID a); BOOL ok = kex_real_unmap(a);
        kex_shm_note_unmap(ok);
        if (!ok) kex_trace("UnmapViewOfFile FAILED (view leaks)", (DWORD)(ULONG_PTR)a, GetLastError(), 0, 0);
        return ok;
    }
}
/* GetProcessTimes: proctime_ext.c */
