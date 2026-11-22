/*
 * laa_ext.c - KernelEx-NG build 123: address space above 2 GB for "large address aware" programs.
 *
 * Why. A 32-bit program whose EXE header carries IMAGE_FILE_LARGE_ADDRESS_AWARE (chrome.exe 159 does) gets 4 GB of
 * address space on 64-bit Windows; Windows 98 gives every program 2 GB (0x00400000-0x7FFFFFFF). Discord's tab ran
 * out of it (builds 120 and 122: free 25 MB, largest hole 4.8 MB; 757 MB held in Chrome's allocator blocks with
 * 123 MB used, 512 MB Chrome emergency reserve) and Chrome stopped drawing the tab at that moment - no more clicks.
 *
 * What. When such a program's own 2 GB cannot hold a reservation, kexnt places it in Windows 98's shared arena
 * (0x80000000-0xBFFFFFFF), the area 98 uses for memory shared between programs, if enough of it stays free.
 * Measured on Windows 98 (probes/lprobe.c, QEMU test VM):
 *   - VirtualAlloc(NULL, n, MEM_RESERVE | 0x08000000 VA_SHARED) reserves there; commit / decommit (zeros on
 *     recommit) / VirtualProtect / release in it work like private memory, also at an address of our choosing;
 *   - Windows does NOT free it when its process ends (exit, killed, crash: the blocks stayed, arena -8 MB each);
 *   - another process CAN free it (VirtualFree MEM_RELEASE -> state free).
 * So kexnt keeps a system-wide table (named mapping KXLAA_TABLE, mutex KXLAA_LOCK) of every such block with its
 * process, and frees the blocks of processes that have ended. Rules, chosen to prefer a leak over a wrong free:
 *   - only NT 6+ programs (kex_peb_active) whose EXE is large address aware; Windows 9x programs never;
 *   - only reservations (MEM_RESERVE) with no address asked, after Windows said "not enough memory" for the
 *     private arena, and at most 32 MB each; the shared arena keeps at least 128 MB free (Chrome's own shared
 *     memory, Windows DLLs) - otherwise the request fails as before;
 *   - a block is freed only (a) by its owner's own VirtualFree(MEM_RELEASE) through kexnt, or (b) by a sweep after
 *     its owner has ended (OpenProcess fails or exit code is not STILL_ACTIVE). Never while the owner lives;
 *   - a sweep frees a block only if Windows still shows an allocation starting at its base with its exact size;
 *     anything else (half-finished entry, changed region) is dropped from the table WITHOUT freeing (leak, noted);
 *   - every change of the table and the matching VirtualAlloc/VirtualFree happen under the mutex.
 * Sweeps: once when a program first reserves 1 MB+ (start of every Chrome process), every 3 s from a small thread
 * in each eligible program, and right after kexnt's TerminateProcess of another process has ended it.
 * Everything is noted in KEXCRASH (lent blocks, refusals, sweeps) - see the notes' texts below.
 */
#include "kexnt_common.h"

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
BOOL kex_peb_active(void);

#define LAA_MAX      4096
#define LAA_KEEP     (128u << 20)        /* shared arena bytes that must stay free */
#define LAA_MAXONE   (32u << 20)         /* biggest single block placed there */
#define SH_LO        0x80000000UL
#define SH_HI        0xC0000000UL
#define VA_SHARED_K  0x08000000UL

typedef struct { DWORD base, size, pid, state; } LENT;     /* state: 0 free slot, 1 in use, 2 being released */
typedef struct { DWORD magic, version, count, lent_bytes; LENT e[LAA_MAX]; } LTABLE;
#define LAA_MAGIC 0x4141414CUL                             /* 'LAAA' */

static LTABLE *g_t;
static HANDLE g_mx;
static volatile LONG g_tinit, g_elig = -1, g_thread;
/* this process's own blocks (only it adds/removes them while it lives): lookups without the global mutex */
static DWORD g_own_base[LAA_MAX], g_own_size[LAA_MAX];
static volatile LONG g_own_n, g_own_lock;
static volatile LONG g_n_lent, g_n_refused, g_kb_lent;

static BOOL table(void)
{
    if (g_t) return TRUE;
    kex_spin_acquire(&g_tinit);
    if (!g_t) {
        HANDLE m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(LTABLE), "KXLAA_TABLE");
        HANDLE x = CreateMutexA(NULL, FALSE, "KXLAA_LOCK");
        if (m && x) {
            LTABLE *t = (LTABLE *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);
            if (t) {
                WaitForSingleObject(x, INFINITE);
                if (t->magic != LAA_MAGIC || t->version != 1) { ZeroMemory(t, sizeof(*t)); t->magic = LAA_MAGIC; t->version = 1; }
                ReleaseMutex(x);
                g_mx = x; g_t = t;                       /* mapping handle kept for the life of the process */
            }
        }
    }
    InterlockedExchange(&g_tinit, 0);
    return g_t != NULL;
}
static void tlock(void)   { DWORD w = WaitForSingleObject(g_mx, INFINITE); (void)w; /* WAIT_ABANDONED = ours too */ }
static void tunlock(void) { ReleaseMutex(g_mx); }

/* is this program large address aware (its EXE header)? */
static BOOL eligible(void)
{
    if (g_elig < 0) {
        BYTE *b = (BYTE *)GetModuleHandleA(NULL); LONG e = 0;
        if (b && !IsBadReadPtr(b, 0x40) && *(WORD *)b == IMAGE_DOS_SIGNATURE) {
            IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + *(LONG *)(b + 0x3C));
            if (!IsBadReadPtr(nt, sizeof(*nt)) && nt->Signature == IMAGE_NT_SIGNATURE &&
                (nt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)) e = 1;
        }
        InterlockedExchange(&g_elig, e);
    }
    return g_elig == 1 && kex_peb_active();
}

static void own_add(DWORD base, DWORD size)
{
    kex_spin_acquire(&g_own_lock);
    if (g_own_n < LAA_MAX) { g_own_base[g_own_n] = base; g_own_size[g_own_n] = size; g_own_n++; }
    InterlockedExchange(&g_own_lock, 0);
}
static void own_del(DWORD base)
{
    LONG i;
    kex_spin_acquire(&g_own_lock);
    for (i = 0; i < g_own_n; i++) if (g_own_base[i] == base) {
        g_own_base[i] = g_own_base[g_own_n - 1]; g_own_size[i] = g_own_size[g_own_n - 1]; g_own_n--; break;
    }
    InterlockedExchange(&g_own_lock, 0);
}
/* does [a, a+n) lie inside one of this process's blocks above 2 GB? (n 0 = just the address) */
BOOL kex_laa_owns(LPCVOID a, SIZE_T n)
{
    DWORD x = (DWORD)(ULONG_PTR)a; LONG i; BOOL r = FALSE;
    if (x < SH_LO || x >= SH_HI || !g_own_n) return FALSE;
    kex_spin_acquire(&g_own_lock);
    for (i = 0; i < g_own_n; i++)
        if (x >= g_own_base[i] && x - g_own_base[i] < g_own_size[i] && (DWORD)n <= g_own_size[i] - (x - g_own_base[i])) { r = TRUE; break; }
    InterlockedExchange(&g_own_lock, 0);
    return r;
}
BOOL kex_laa_is_base(LPCVOID a)
{
    DWORD x = (DWORD)(ULONG_PTR)a; LONG i; BOOL r = FALSE;
    if (x < SH_LO || x >= SH_HI || !g_own_n) return FALSE;
    kex_spin_acquire(&g_own_lock);
    for (i = 0; i < g_own_n; i++) if (g_own_base[i] == x) { r = TRUE; break; }
    InterlockedExchange(&g_own_lock, 0);
    return r;
}

/* shared arena: free bytes in all */
static DWORD shared_free(void)
{
    DWORD a = SH_LO, fr = 0; MEMORY_BASIC_INFORMATION m;
    while (a < SH_HI && VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) >= sizeof(m) && m.RegionSize) {
        if (m.State == MEM_FREE) fr += (DWORD)m.RegionSize;
        a = (DWORD)(ULONG_PTR)m.BaseAddress + (DWORD)m.RegionSize;
    }
    return fr;
}
/* Windows still shows one allocation that starts at base and is exactly size long? */
static BOOL region_is(DWORD base, DWORD size)
{
    DWORD a = base, tot = 0; MEMORY_BASIC_INFORMATION m;
    while (VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) >= sizeof(m) && m.RegionSize &&
           m.State != MEM_FREE && (DWORD)(ULONG_PTR)m.AllocationBase == base) {
        tot += (DWORD)m.RegionSize; a = (DWORD)(ULONG_PTR)m.BaseAddress + (DWORD)m.RegionSize;
        if (tot > size) return FALSE;
    }
    if (tot != size) return FALSE;
    /* the next region must not belong to the same allocation (checked by the loop) */
    return TRUE;
}
static int t_add_locked(DWORD base, DWORD size)
{
    int i;
    for (i = 0; i < LAA_MAX; i++) if (!g_t->e[i].state) {
        g_t->e[i].base = base; g_t->e[i].size = size; g_t->e[i].pid = GetCurrentProcessId(); g_t->e[i].state = 1;
        g_t->count++; g_t->lent_bytes += size;
        return i;
    }
    return -1;
}

static BOOL pid_alive(DWORD pid)
{
    HANDLE h; DWORD code = 0;
    if (pid == GetCurrentProcessId()) return TRUE;
    if (!(h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid))) {
        DWORD e = GetLastError();
        /* a shortage is no proof that it ended; anything else means there is no such process (any more) */
        return e == ERROR_NOT_ENOUGH_MEMORY || e == ERROR_OUTOFMEMORY || e == ERROR_NO_SYSTEM_RESOURCES;
    }
    if (!GetExitCodeProcess(h, &code)) code = STILL_ACTIVE;
    CloseHandle(h);
    return code == STILL_ACTIVE;
}

/* free the blocks of ended processes (only_pid != 0: only that process, known to have ended) */
static void sweep(DWORD only_pid)
{
    int i; DWORD freed = 0, kb = 0, dropped = 0, last_pid = 0;
    if (!table() || !g_t->count) return;
    tlock();
    for (i = 0; i < LAA_MAX; i++) {
        LENT *e = &g_t->e[i];
        if (!e->state || e->pid == GetCurrentProcessId()) continue;
        if (only_pid ? e->pid != only_pid : pid_alive(e->pid)) continue;
        if (e->state == 1 && region_is(e->base, e->size) && VirtualFree((LPVOID)(ULONG_PTR)e->base, 0, MEM_RELEASE)) {
            freed++; kb += e->size >> 10;
        } else dropped++;                     /* not exactly ours any more (or half released): leave it alone */
        last_pid = e->pid;
        g_t->lent_bytes -= e->size; g_t->count--;
        e->state = 0; e->base = e->size = e->pid = 0;
    }
    tunlock();
    if (freed || dropped) {
        static LONG k;
        if (InterlockedIncrement(&k) <= 40)
            kex_crashnote("LAA: blocks above 2 GB of an ended process freed (blocks freed, KB, entries dropped without freeing, process)",
                          freed, kb, dropped, last_pid);
    }
}
static DWORD WINAPI sweeper(LPVOID p)
{
    (void)p;
    for (;;) { Sleep(3000); if (g_t && g_t->count) sweep(0); }
    return 0;
}
/* kex_VirtualAlloc: a 1 MB+ reservation is being made (start of every Chrome process) - one sweep, start the thread */
void kex_laa_seen_reserve(void)
{
    if (g_thread || !eligible()) return;
    if (InterlockedExchange(&g_thread, 1)) return;
    if (!table()) return;
    sweep(0);
    {   DWORD tid; HANDLE h = CreateThread(NULL, 0x10000, sweeper, NULL, 0, &tid);
        if (h) { SetThreadPriority(h, THREAD_PRIORITY_BELOW_NORMAL); CloseHandle(h); } }
}
/* kex_TerminateProcess of another process: once it has ended, free its blocks at once */
void kex_laa_process_ended(HANDLE ph, DWORD pid)
{
    if (!pid || !g_t || !g_t->count) return;
    if (WaitForSingleObject(ph, 500) != WAIT_OBJECT_0) return;      /* not ended yet: the 3 s sweep will do it */
    sweep(pid);
}

static void note_refused(DWORD n, DWORD why, DWORD fr)
{
    InterlockedIncrement(&g_n_refused);
    {   static LONG k; if (InterlockedIncrement(&k) <= 20)
            kex_crashnote("LAA: 2 GB full, block NOT placed above 2 GB (size, reason 1 too big / 2 shared arena would drop below 128 MB / 3 table full / 4 Windows refused, shared free KB, lent so far KB)",
                          n, why, fr >> 10, (DWORD)g_kb_lent); }
}
static LPVOID lent_note(LPVOID r, DWORD n, DWORD fr, DWORD how)
{
    LONG c = InterlockedIncrement(&g_n_lent); LONG kb = InterlockedExchangeAdd(&g_kb_lent, (LONG)(n >> 10)) + (LONG)(n >> 10);
    if (c <= 30 || (c % 50) == 0)
        kex_crashnote(how ? "LAA: block placed above 2 GB at the address the program asked (address, size, shared free KB after, lent by this process KB)"
                          : "LAA: 2 GB full - block placed above 2 GB (address, size, shared free KB after, lent by this process KB)",
                      (DWORD)(ULONG_PTR)r, n, (fr - n) >> 10, (DWORD)kb);
    return r;
}

/* Windows said "not enough memory" for a reservation with no address: place it above 2 GB (or NULL) */
LPVOID kex_laa_lend(SIZE_T n, DWORD type, DWORD prot)
{
    DWORD fr, align, sz = (DWORD)((n + 0xFFFF) & ~0xFFFFUL); LPVOID r = NULL; int k, slot;
    if (!eligible() || !(type & MEM_RESERVE) || !sz) return NULL;
    if (sz > LAA_MAXONE) { note_refused(sz, 1, 0); return NULL; }
    if (!table()) return NULL;
    kex_laa_seen_reserve();
    /* alignment as the allocators want it: 2 MB for multiples of 2 MB (PartitionAlloc super pages), else the
     * largest power of two <= size (V8 pages: 256 KB), at least 64 KB */
    if (!(sz & 0x1FFFFF)) align = 0x200000;
    else { align = 0x10000; while (align * 2 <= sz && align < 0x200000) align *= 2; }
    tlock();
    fr = shared_free();
    if (fr < sz + align || fr - sz - align < LAA_KEEP) { tunlock(); note_refused(sz, 2, fr); return NULL; }
    if (g_t->count >= LAA_MAX - 1) { tunlock(); note_refused(sz, 3, fr); return NULL; }
    for (k = 0; k < 4 && !r; k++) {
        BYTE *big = (BYTE *)VirtualAlloc(NULL, sz + align, MEM_RESERVE | VA_SHARED_K, PAGE_NOACCESS);
        DWORD al;
        if (!big) break;
        al = ((DWORD)(ULONG_PTR)big + align - 1) & ~(align - 1);
        VirtualFree(big, 0, MEM_RELEASE);
        r = VirtualAlloc((LPVOID)(ULONG_PTR)al, sz, (type & (MEM_RESERVE | MEM_COMMIT)) | VA_SHARED_K, prot);
    }
    if (!r) r = VirtualAlloc(NULL, sz, (type & (MEM_RESERVE | MEM_COMMIT)) | VA_SHARED_K, prot);   /* unaligned last try */
    if (!r || (DWORD)(ULONG_PTR)r < SH_LO) {
        if (r) VirtualFree(r, 0, MEM_RELEASE);
        tunlock(); note_refused(sz, 4, fr); return NULL;
    }
    slot = t_add_locked((DWORD)(ULONG_PTR)r, sz);
    if (slot < 0) { VirtualFree(r, 0, MEM_RELEASE); tunlock(); note_refused(sz, 3, fr); return NULL; }
    own_add((DWORD)(ULONG_PTR)r, sz);
    tunlock();
    return lent_note(r, sz, fr, 0);
}

/* a reservation at an address in the shared arena, from a program that already has blocks there (allocators
 * retrying at an aligned address after freeing a bigger block): taken if that space is free and the budget allows */
LPVOID kex_laa_lend_at(LPVOID a, SIZE_T n, DWORD type, DWORD prot)
{
    DWORD x = (DWORD)(ULONG_PTR)a, sz = (DWORD)((n + 0xFFFF) & ~0xFFFFUL), fr; LPVOID r; MEMORY_BASIC_INFORMATION m;
    if (!eligible() || !(type & MEM_RESERVE) || !g_n_lent || (x & 0xFFFF) || x < SH_LO || x + sz > SH_HI || x + sz < x) return NULL;
    if (sz > LAA_MAXONE || !table()) return NULL;
    {   /* only while the program's own 2 GB are really tight (largest hole below 64 MB) - a random address hint
         * up there must not use the shared arena while there is room below 2 GB */
        DWORD at = 0x10000, mx = 0; MEMORY_BASIC_INFORMATION q;
        while (at < SH_LO && VirtualQuery((LPCVOID)(ULONG_PTR)at, &q, sizeof(q)) >= sizeof(q) && q.RegionSize) {
            if (q.State == MEM_FREE && q.RegionSize > mx) mx = (DWORD)q.RegionSize;
            at = (DWORD)(ULONG_PTR)q.BaseAddress + (DWORD)q.RegionSize;
        }
        if (mx >= (64u << 20)) return NULL;
    }
    if (!VirtualQuery(a, &m, sizeof(m)) || m.State != MEM_FREE || (DWORD)(ULONG_PTR)m.BaseAddress + (DWORD)m.RegionSize - x < sz) return NULL;
    tlock();
    fr = shared_free();
    if (fr < sz || fr - sz < LAA_KEEP || g_t->count >= LAA_MAX - 1) { tunlock(); note_refused(sz, fr < sz || fr - sz < LAA_KEEP ? 2 : 3, fr); return NULL; }
    r = VirtualAlloc(a, sz, (type & (MEM_RESERVE | MEM_COMMIT)) | VA_SHARED_K, prot);
    if (!r || r != a) { if (r) VirtualFree(r, 0, MEM_RELEASE); tunlock(); return NULL; }
    if (t_add_locked(x, sz) < 0) { VirtualFree(r, 0, MEM_RELEASE); tunlock(); return NULL; }
    own_add(x, sz);
    tunlock();
    return lent_note(r, sz, fr, 1);
}

/* the program releases one of its blocks (VirtualFree base, 0, MEM_RELEASE) */
BOOL kex_laa_release(LPVOID a)
{
    DWORD x = (DWORD)(ULONG_PTR)a; int i; BOOL r = FALSE; DWORD le = 0;
    if (!table()) return FALSE;
    tlock();
    for (i = 0; i < LAA_MAX; i++) {
        LENT *e = &g_t->e[i];
        if (e->state == 1 && e->base == x && e->pid == GetCurrentProcessId()) {
            e->state = 2;                                    /* being released: a sweep never frees it */
            r = VirtualFree(a, 0, MEM_RELEASE); le = GetLastError();
            if (r) { g_t->lent_bytes -= e->size; g_t->count--; e->state = 0; e->base = e->size = e->pid = 0; own_del(x); }
            else e->state = 1;
            break;
        }
    }
    /* build 128: own_del moved inside the lock. Before, between tunlock() and own_del() another thread of the
     * same process could be lent the very same address (PartitionAlloc frees and re-reserves 2 MB blocks from
     * several threads); own_del then removed THAT thread's new entry, and its later VirtualFree(MEM_RELEASE) was
     * refused as "not ours" - Chrome's CHECK in page_allocator_internals_win.h:186 (renderer crash, build 127). */
    tunlock();
    if (!r) {
        static LONG k; if (InterlockedIncrement(&k) <= 20)
            kex_crashnote("LAA: release of a block above 2 GB FAILED (address, in the table for this process 1/0, error, -)", x, i < LAA_MAX, le ? le : GetLastError(), 0);
        if (!le) le = ERROR_INVALID_ADDRESS;
    }
    SetLastError(le);
    return r;
}

/* the exit note (crashlog_ext.c log_exit): what this process still holds above 2 GB */
void kex_laa_exit_note(void)
{
    if (g_n_lent || g_n_refused) {
        DWORD kb = 0; LONG i;
        for (i = 0; i < g_own_n; i++) kb += g_own_size[i] >> 10;
        kex_crashnote("LAA: at exit (blocks placed above 2 GB in all, refused, still held now, KB held - freed by kexnt after this process has ended)",
                      (DWORD)g_n_lent, (DWORD)g_n_refused, (DWORD)g_own_n, kb);
    }
}
