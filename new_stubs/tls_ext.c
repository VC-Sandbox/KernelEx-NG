/*
 * tls_ext.c - KernelEx-NG: static (implicit, __declspec(thread) / thread_local) TLS for DLLs loaded
 * with LoadLibrary on Windows 98 SE.
 *
 * Windows 98 sets up the TLS directory (IMAGE_DIRECTORY_ENTRY_TLS) only for the exe and the DLLs
 * loaded with it at process start. A DLL loaded later with LoadLibrary is mapped and run, but its
 * TLS index variable is left at its file value (0) and no thread gets a copy of its TLS template,
 * so the first thread_local access reads another module's slot. Windows Vista and later handle this
 * case (chrome.dll relies on it, and has 6 TLS callbacks). Documented behaviour reproduced here:
 *
 *   - a TLS slot is allocated (TlsAlloc) and written to the module's AddressOfIndex;
 *   - every thread gets its own block: template (StartAddressOfRawData..End) + SizeOfZeroFill zero
 *     bytes, aligned as the TLS Characteristics ask, stored in that slot. Compiled code reads it as
 *     fs:[2Ch][index] - on Windows 98 fs:[2Ch] is the same per-thread slot array TlsSetValue writes;
 *   - threads that already exist get a block too (as on Vista+), written into their slot array
 *     directly (found through the thread ID -> TDB -> TIB);
 *   - TLS callbacks run with DLL_PROCESS_ATTACH after the load, and with DLL_THREAD_ATTACH /
 *     DLL_THREAD_DETACH from kexnt's own thread notifications.
 *
 * Which modules need it: a module list (toolhelp) is taken at the first LoadLibrary call; modules in
 * it were set up by Windows. Any module that appears later and has a TLS directory is set up by us -
 * that also covers the DLLs a loaded DLL pulls in through its imports.
 *
 * Windows runs a DLL's entry point inside LoadLibrary. When kexnt's DLL-entry hook is live (veh_ext.c),
 * kex_tls_early sets the module up just before its DLL_PROCESS_ATTACH, as NT does; otherwise (hook not
 * installable) the setup happens after LoadLibrary returns.
 */
#include "kexnt_common.h"
#include <tlhelp32.h>
void kex_crashlog_text(const char *s);   /* crashlog_ext.c */

#define TLS_MAX_MODS  256   /* build 47: was 32 - Chromium has 40+ modules with static TLS; the 33rd (vk_swiftshader.dll) got none */
#define KNOWN_MAX     512

typedef struct {
    HMODULE  h;
    DWORD    index;
    DWORD   *pindex;
    BYTE    *start;
    DWORD    rawlen, zerofill, align;
    PIMAGE_TLS_CALLBACK *callbacks;
    DWORD    pending;      /* build 48: being set up by some thread (no g_cs held meanwhile) */
} TLSMOD;

static CRITICAL_SECTION g_cs;
static LONG    g_cs_init;
static TLSMOD  g_mods[TLS_MAX_MODS];
static int     g_nmods;
static HMODULE g_known[KNOWN_MAX];
static int     g_nknown;
static BOOL    g_snapshot_done;
static DWORD   g_stat_modules;

/* g_cs is initialised from kexnt's DLL_PROCESS_ATTACH (kex_tls_init), before any caller can get here */
static DWORD g_inload = TLS_OUT_OF_INDEXES;      /* per-thread depth of kexnt LoadLibrary calls */
void kex_tls_init(void)
{
    if (InterlockedExchange(&g_cs_init, 1) == 0) { InitializeCriticalSection(&g_cs); g_inload = TlsAlloc(); }
}

/* loader_ext brackets every LoadLibrary* it forwards; the DLL-entry hook (veh_ext.c) only acts inside one */
/* TlsGetValue sets the last error to 0 - these must leave the caller's (LoadLibrary's) error alone */
void kex_tls_enter(void)
{
    DWORD le = GetLastError();
    if (g_inload != TLS_OUT_OF_INDEXES) TlsSetValue(g_inload, (LPVOID)((ULONG_PTR)TlsGetValue(g_inload) + 1));
    SetLastError(le);
}
void kex_tls_leave(void)
{
    ULONG_PTR d; DWORD le = GetLastError();
    if (g_inload == TLS_OUT_OF_INDEXES) return;
    d = (ULONG_PTR)TlsGetValue(g_inload);
    TlsSetValue(g_inload, (LPVOID)(d ? d - 1 : 0));
    SetLastError(le);
}
BOOL kex_tls_in_load(void)
{
    DWORD le = GetLastError(); BOOL r;
    r = g_inload != TLS_OUT_OF_INDEXES && TlsGetValue(g_inload) != NULL;
    SetLastError(le);
    return r;
}
static void lock(void) { kex_tls_init(); EnterCriticalSection(&g_cs); }
static void unlock(void) { LeaveCriticalSection(&g_cs); }

static BOOL known(HMODULE h)
{
    int i;
    for (i = 0; i < g_nknown; i++) if (g_known[i] == h) return TRUE;
    return FALSE;
}
static void add_known(HMODULE h) { if (!known(h) && g_nknown < KNOWN_MAX) g_known[g_nknown++] = h; }

/* every module of this process; calls fn for each (returns count) */
static int each_module(void (*fn)(HMODULE))
{
    MODULEENTRY32 me; HANDLE s; int n = 0;
    s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (s == INVALID_HANDLE_VALUE) return -1;
    me.dwSize = sizeof(me);
    if (Module32First(s, &me)) do { fn(me.hModule); n++; me.dwSize = sizeof(me); } while (Module32Next(s, &me));
    CloseHandle(s);
    return n;
}

static PIMAGE_TLS_DIRECTORY32 tls_dir(HMODULE h)
{
    BYTE *b = (BYTE *)h;
    IMAGE_NT_HEADERS32 *nt;
    DWORD rva, size;
    if (!b || IsBadReadPtr(b, 0x40) || *(WORD *)b != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (IMAGE_NT_HEADERS32 *)(b + *(LONG *)(b + 0x3C));
    if (IsBadReadPtr(nt, sizeof(*nt)) || nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS) return NULL;
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    if (!rva || size < sizeof(IMAGE_TLS_DIRECTORY32) || rva >= nt->OptionalHeader.SizeOfImage) return NULL;
    return (PIMAGE_TLS_DIRECTORY32)(b + rva);
}

/* still the same mapping we set up (not freed / reloaded since) */
static BOOL mod_alive(const TLSMOD *m)
{
    return !IsBadReadPtr(m->h, 2) && *(WORD *)m->h == IMAGE_DOS_SIGNATURE &&
           !IsBadReadPtr(m->pindex, 4) && *m->pindex == m->index;
}

static void *new_block(const TLSMOD *m)
{
    DWORD a = m->align < 8 ? 8 : m->align, total = m->rawlen + m->zerofill;
    BYTE *raw = (BYTE *)HeapAlloc(GetProcessHeap(), 0, total + a + 4), *blk;
    if (!raw) return NULL;
    blk = (BYTE *)(((ULONG_PTR)raw + 4 + a - 1) & ~(ULONG_PTR)(a - 1));
    ((void **)blk)[-1] = raw;
    if (m->rawlen) memcpy(blk, m->start, m->rawlen);
    if (m->zerofill) memset(blk + m->rawlen, 0, m->zerofill);
    return blk;
}
static void free_block(void *blk) { if (blk) HeapFree(GetProcessHeap(), 0, ((void **)blk)[-1]); }

/* only callbacks that point into the module's own image are called (a damaged TLS directory - e.g. image
 * data that was loaded wrong - must not send us to a random address) */
static void run_callbacks(const TLSMOD *m, DWORD reason)
{
    PIMAGE_TLS_CALLBACK *cb = m->callbacks;
    BYTE *lo = (BYTE *)m->h, *hi;
    IMAGE_NT_HEADERS32 *nt;
    if (!cb || IsBadReadPtr(lo, 0x40)) return;
    nt = (IMAGE_NT_HEADERS32 *)(lo + *(LONG *)(lo + 0x3C));
    if (IsBadReadPtr(nt, sizeof(*nt))) return;
    hi = lo + nt->OptionalHeader.SizeOfImage;
    if ((BYTE *)cb < lo || (BYTE *)cb >= hi) return;
    for (; !IsBadReadPtr(cb, 4) && *cb; cb++) {
        if ((BYTE *)*cb < lo || (BYTE *)*cb >= hi) break;
        (*cb)((PVOID)m->h, reason, NULL);
    }
}

/* Windows 98: thread ID = TDB ^ obfuscator; TIB = TDB + 8; TIB+2Ch = the thread's TLS slot array. */
static BYTE *cur_tib(void) { BYTE *t; __asm__ volatile("movl %%fs:0x18, %0" : "=r"(t)); return t; }


static DWORD *slots_of_thread(DWORD tid)
{
    BYTE *tdb, *tib;
    DWORD obf = (DWORD)(ULONG_PTR)(cur_tib() - 8) ^ GetCurrentThreadId();
    tdb = (BYTE *)(ULONG_PTR)(tid ^ obf);
    if ((ULONG_PTR)tdb < 0x80000000UL || IsBadReadPtr(tdb, 0x40)) return NULL;
    if (*(WORD *)tdb != 7) return NULL;                         /* K32 object type: thread */
    tib = tdb + 8;
    if (*(BYTE **)(tib + 0x18) != tib) return NULL;             /* TIB.Self */
    return *(DWORD **)(tib + 0x2C);
}

/* give every other thread of this process a block for slot m->index */
static void existing_threads(const TLSMOD *m)
{
    THREADENTRY32 te; HANDLE s; DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId();
    s = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (s == INVALID_HANDLE_VALUE) return;
    te.dwSize = sizeof(te);
    if (Thread32First(s, &te)) do {
        if (te.th32OwnerProcessID == pid && te.th32ThreadID != me) {
            DWORD *slots = slots_of_thread(te.th32ThreadID);
            if (slots && !IsBadWritePtr(&slots[m->index], 4)) {
                void *b = new_block(m);
                if (b) slots[m->index] = (DWORD)(ULONG_PTR)b;
            }
        }
        te.dwSize = sizeof(te);
    } while (Thread32Next(s, &te));
    CloseHandle(s);
}

/* Build 48 - lock order. Windows 98's loader holds KERNEL32's own lock while it runs DllMain (and so
 * kex_tls_early); Toolhelp, GetModuleFileName and TlsAlloc take that lock too. Up to build 47 setup_module ran
 * all of those while holding g_cs, and kex_tls_after_load took g_cs and then Toolhelp: thread A (after its
 * LoadLibrary) held g_cs and waited for KERNEL32's lock, thread B (inside a LoadLibrary, KERNEL32's lock held)
 * waited for g_cs in kex_tls_early - a deadlock that only shows with many threads loading DLLs at once (Chrome).
 * Now g_cs only guards our own tables (no Windows call inside it); a module being set up is claimed first
 * ("pending") so two threads never set up the same one. */
static BOOL claimed(HMODULE h)
{
    int i;
    for (i = 0; i < g_nmods; i++) if (g_mods[i].h == h && (g_mods[i].pending || mod_alive(&g_mods[i]))) return TRUE;
    return FALSE;
}

/* set up one module (called WITHOUT g_cs); returns its record (copied out) or FALSE */
static BOOL setup_module(HMODULE h, TLSMOD *out)
{
    PIMAGE_TLS_DIRECTORY32 td = tls_dir(h);
    TLSMOD m; void *blk; int i, slot; DWORD old_index = TLS_OUT_OF_INDEXES;
    if (!td) return FALSE;
    memset(&m, 0, sizeof(m));
    m.h = h;
    m.pindex = (DWORD *)(ULONG_PTR)td->AddressOfIndex;
    m.start = (BYTE *)(ULONG_PTR)td->StartAddressOfRawData;
    m.rawlen = td->EndAddressOfRawData > td->StartAddressOfRawData ? td->EndAddressOfRawData - td->StartAddressOfRawData : 0;
    m.zerofill = td->SizeOfZeroFill;
    m.align = (td->Characteristics >> 20) & 0xF ? 1u << (((td->Characteristics >> 20) & 0xF) - 1) : 8;
    m.callbacks = (PIMAGE_TLS_CALLBACK *)(ULONG_PTR)td->AddressOfCallBacks;
    if (IsBadWritePtr(m.pindex, 4) || (m.rawlen && IsBadReadPtr(m.start, m.rawlen))) return FALSE;
    /* claim a record: a dead one of the same module (FreeLibrary + reload keeps its slot), else a new one */
    lock();
    if (claimed(h)) { unlock(); return FALSE; }
    for (slot = 0; slot < g_nmods; slot++) if (g_mods[slot].h == h) break;
    if (slot == g_nmods) {
        if (g_nmods >= TLS_MAX_MODS) slot = -1;
        else { memset(&g_mods[slot], 0, sizeof(g_mods[slot])); g_mods[slot].h = h; g_mods[slot].index = TLS_OUT_OF_INDEXES; g_nmods++; }
    }
    if (slot >= 0) { old_index = g_mods[slot].index; g_mods[slot].pending = 1; }
    unlock();
    if (slot < 0) {
        char t[MAX_PATH + 80]; lstrcpyA(t, "--- static TLS FAILED (kexnt module table full): ");
        GetModuleFileNameA(h, t + lstrlenA(t), MAX_PATH); kex_crashlog_text(t);
        return FALSE;
    }
    if (old_index != TLS_OUT_OF_INDEXES) m.index = old_index;
    else if ((m.index = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
        char t[MAX_PATH + 80]; lstrcpyA(t, "--- static TLS FAILED (no TLS slot left): ");
        GetModuleFileNameA(h, t + lstrlenA(t), MAX_PATH); kex_crashlog_text(t);
        lock(); g_mods[slot].pending = 0; unlock();
        return FALSE;
    }
    if (!(blk = new_block(&m))) {
        lock(); g_mods[slot].pending = 0; g_mods[slot].index = m.index; unlock();
        return FALSE;
    }
    TlsSetValue(m.index, blk);
    *m.pindex = m.index;
    existing_threads(&m);
    lock();
    m.pending = 0;
    g_mods[slot] = m;
    g_stat_modules++;
    unlock();
    {   char t[MAX_PATH + 80]; int l; lstrcpyA(t, "--- static TLS set up before DllMain: slot ");
        l = lstrlenA(t); if (m.index >= 1000) t[l++] = (char)('0' + m.index / 1000 % 10); if (m.index >= 100) t[l++] = (char)('0' + m.index / 100 % 10);
        t[l++] = (char)('0' + m.index / 10 % 10); t[l++] = (char)('0' + m.index % 10); t[l++] = ' '; t[l] = 0;
        GetModuleFileNameA(h, t + l, MAX_PATH); kex_crashlog_text(t); }
    *out = m;
    (void)i;
    return TRUE;
}

/* new modules found by the post-load scan */
static HMODULE g_scan[KNOWN_MAX];
static int     g_nscan;
static void snap_scan(HMODULE h) { if (g_nscan < KNOWN_MAX) g_scan[g_nscan++] = h; }

/* Called by loader_ext before the native LoadLibrary: the first time, remember what Windows set up.
 * (Toolhelp outside g_cs; g_scan is only used under g_scanlk.) */
static volatile LONG g_scanlk;
static HMODULE *scan_modules(int *count)
{
    HMODULE *r = NULL; int n;
    kex_spin_acquire(&g_scanlk);
    g_nscan = 0;
    each_module(snap_scan);
    n = g_nscan;
    if (n && (r = (HMODULE *)HeapAlloc(GetProcessHeap(), 0, sizeof(HMODULE) * n))) memcpy(r, g_scan, sizeof(HMODULE) * n);
    InterlockedExchange(&g_scanlk, 0);
    *count = r ? n : 0;
    return r;
}
void kex_tls_before_load(void)
{
    HMODULE *l; int n, i;
    if (g_snapshot_done) return;
    l = scan_modules(&n);
    lock();
    if (!g_snapshot_done) { for (i = 0; i < n; i++) add_known(l[i]); g_snapshot_done = TRUE; }
    unlock();
    if (l) HeapFree(GetProcessHeap(), 0, l);
}

/* Called by loader_ext after a successful normal load. */
void kex_tls_after_load(HMODULE h)
{
    TLSMOD *todo;   /* build 48: on the heap - 256 records are 9 KB */
    HMODULE *l = NULL; int n = 0, nl = 0, i, isknown;
    if (!h || !g_snapshot_done) return;
    lock(); isknown = known(h); unlock();
    if (!(todo = (TLSMOD *)HeapAlloc(GetProcessHeap(), 0, sizeof(TLSMOD) * TLS_MAX_MODS))) return;
    if (!isknown) {
        l = scan_modules(&nl);
        for (i = 0; i < nl && n < TLS_MAX_MODS; i++) {
            HMODULE m = l[i]; int was;
            lock(); was = known(m); if (!was) add_known(m); unlock();
            if (was || !tls_dir(m)) continue;
            if (setup_module(m, &todo[n])) n++;
        }
    } else {
        /* a module we set up earlier that was freed and loaded again: its index variable is back at 0 */
        int dead = 0;
        lock(); for (i = 0; i < g_nmods; i++) if (g_mods[i].h == h && !g_mods[i].pending && !mod_alive(&g_mods[i])) { dead = 1; break; } unlock();
        if (dead && tls_dir(h) && setup_module(h, &todo[n])) n++;
    }
    for (i = 0; i < n; i++) run_callbacks(&todo[i], DLL_PROCESS_ATTACH);
    if (l) HeapFree(GetProcessHeap(), 0, l);
    HeapFree(GetProcessHeap(), 0, todo);
}

/* Called by the DLL-entry hook just before Windows runs h's entry point with DLL_PROCESS_ATTACH, for loads
 * that came through kexnt's LoadLibrary: set up h's static TLS and run its TLS callbacks first, as NT does.
 * build 44/45: also a module with a dead record (freed and loaded again), and no "known" test (Windows 98
 * reuses a freed DLL's address range, and g_known is keyed by address). */
void kex_tls_early(HMODULE h)
{
    TLSMOD m;
    if (!h || !g_snapshot_done || !tls_dir(h)) return;
    lock(); add_known(h); unlock();
    if (setup_module(h, &m)) run_callbacks(&m, DLL_PROCESS_ATTACH);
}

static int copy_alive(TLSMOD *out)
{
    int n = 0, i;
    if (!g_nmods) return 0;
    lock();
    for (i = 0; i < g_nmods; i++) if (!g_mods[i].pending && mod_alive(&g_mods[i])) out[n++] = g_mods[i];
    unlock();
    return n;
}

void kex_tls_thread_attach(void)
{
    TLSMOD *l; int n, i;
    if (!g_nmods) return;
    if (!(l = (TLSMOD *)HeapAlloc(GetProcessHeap(), 0, sizeof(TLSMOD) * TLS_MAX_MODS))) return;
    n = copy_alive(l);
    for (i = 0; i < n; i++) {
        if (!TlsGetValue(l[i].index)) { void *b = new_block(&l[i]); if (b) TlsSetValue(l[i].index, b); }
        run_callbacks(&l[i], DLL_THREAD_ATTACH);
    }
    HeapFree(GetProcessHeap(), 0, l);
}

void kex_tls_thread_detach(void)
{
    TLSMOD *l; int n, i;
    if (!g_nmods) return;
    if (!(l = (TLSMOD *)HeapAlloc(GetProcessHeap(), 0, sizeof(TLSMOD) * TLS_MAX_MODS))) return;
    n = copy_alive(l);
    for (i = 0; i < n; i++) {
        void *b;
        run_callbacks(&l[i], DLL_THREAD_DETACH);
        if ((b = TlsGetValue(l[i].index))) { TlsSetValue(l[i].index, NULL); free_block(b); }
    }
    HeapFree(GetProcessHeap(), 0, l);
}

/* diagnostics: number of modules whose TLS kexnt has set up */
DWORD KEXAPI kex_KexTlsModules(void) { return g_stat_modules; }
