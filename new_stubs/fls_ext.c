/*
 * fls_ext.c - KernelEx-NG Phase 2: Fiber Local Storage for Windows 98 SE.
 *
 * Every MSVC CRT since VS2005 calls FlsAlloc at startup (per-thread CRT data with a
 * destructor callback), so this blocks process start for Chromium and most modern apps.
 *
 * Model: one Win98 TLS slot points to a per-thread block of FLS_MAX values. Blocks are
 * linked in a global list so FlsFree can run the callback for every thread's value
 * (NT semantics). On DLL_THREAD_DETACH the callbacks run for the exiting thread.
 *
 * Limitation: storage is per THREAD, not per fiber (Win98 fibers share it). Chromium
 * does not combine fibers with FLS; documented in ARCHITECTURE.md.
 * Callbacks are not run at process exit (DLL_PROCESS_DETACH with lpReserved != NULL):
 * the DLL owning the callback may already be unmapped; NT's behaviour here is not
 * relied on by the CRT, which only frees memory in it.
 */
#include "fls_ext.h"

#define FLS_MAX 128

typedef struct fls_block {
    struct fls_block *next, *prev;
    PVOID slot[FLS_MAX];
} fls_block;

static CRITICAL_SECTION       g_fls_cs;
volatile LONG kex_fls_ready;
static fls_block              g_fls_head;
static PFLS_CALLBACK_FUNCTION g_fls_cb[FLS_MAX];
static volatile BYTE          g_fls_used[FLS_MAX];
static DWORD                  g_fls_tls = TLS_OUT_OF_INDEXES;

static BOOL fls_valid(DWORD i) { return i > 0 && i < FLS_MAX && g_fls_used[i]; }

DWORD KEXAPI kex_FlsAlloc(PFLS_CALLBACK_FUNCTION cb)
{
    DWORD i;
    EnterCriticalSection(&g_fls_cs);
    for (i = 1; i < FLS_MAX; i++) {              /* index 0 never handed out */
        if (!g_fls_used[i]) {
            fls_block *b;
            for (b = g_fls_head.next; b != &g_fls_head; b = b->next) b->slot[i] = NULL;
            g_fls_cb[i] = cb;
            g_fls_used[i] = 1;
            LeaveCriticalSection(&g_fls_cs);
            return i;
        }
    }
    LeaveCriticalSection(&g_fls_cs);
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FLS_OUT_OF_INDEXES;
}

BOOL KEXAPI kex_FlsFree(DWORD i)
{
    PFLS_CALLBACK_FUNCTION cb;
    EnterCriticalSection(&g_fls_cs);
    if (!fls_valid(i)) { LeaveCriticalSection(&g_fls_cs); SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    cb = g_fls_cb[i];
    g_fls_used[i] = 0;                           /* new Get/Set on this index now fail */
    for (;;) {                                   /* run callbacks outside the lock */
        fls_block *b;
        PVOID v = NULL;
        for (b = g_fls_head.next; b != &g_fls_head; b = b->next)
            if (b->slot[i]) { v = b->slot[i]; b->slot[i] = NULL; break; }
        if (!v) break;
        if (cb) { LeaveCriticalSection(&g_fls_cs); cb(v); EnterCriticalSection(&g_fls_cs); }
    }
    g_fls_cb[i] = NULL;
    LeaveCriticalSection(&g_fls_cs);
    return TRUE;
}

PVOID KEXAPI kex_FlsGetValue(DWORD i)
{
    fls_block *b;
    if (!fls_valid(i)) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    b = (fls_block *)TlsGetValue(g_fls_tls);
    SetLastError(ERROR_SUCCESS);                 /* same contract as TlsGetValue */
    return b ? b->slot[i] : NULL;
}

BOOL KEXAPI kex_FlsSetValue(DWORD i, PVOID v)
{
    fls_block *b;
    if (!fls_valid(i)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    b = (fls_block *)TlsGetValue(g_fls_tls);
    if (!b) {
        if (!v) return TRUE;                     /* nothing to store, avoid allocating */
        b = (fls_block *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*b));
        if (!b) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        EnterCriticalSection(&g_fls_cs);
        b->prev = g_fls_head.prev; b->next = &g_fls_head;
        g_fls_head.prev->next = b; g_fls_head.prev = b;
        LeaveCriticalSection(&g_fls_cs);
        TlsSetValue(g_fls_tls, b);
    }
    b->slot[i] = v;
    return TRUE;
}

BOOL kex_fls_init(void)
{
    InitializeCriticalSection(&g_fls_cs); kex_fls_ready = 1;
    g_fls_head.next = g_fls_head.prev = &g_fls_head;
    g_fls_tls = TlsAlloc();
    return g_fls_tls != TLS_OUT_OF_INDEXES;
}

void kex_fls_thread_detach(void)
{
    fls_block *b;
    DWORD i;
    if (g_fls_tls == TLS_OUT_OF_INDEXES) return;
    b = (fls_block *)TlsGetValue(g_fls_tls);
    if (!b) return;
    for (i = 1; i < FLS_MAX; i++) {
        PFLS_CALLBACK_FUNCTION cb;
        PVOID v;
        EnterCriticalSection(&g_fls_cs);
        v = b->slot[i]; b->slot[i] = NULL;
        cb = g_fls_used[i] ? g_fls_cb[i] : NULL;
        LeaveCriticalSection(&g_fls_cs);
        if (v && cb) cb(v);
    }
    EnterCriticalSection(&g_fls_cs);
    b->prev->next = b->next; b->next->prev = b->prev;
    LeaveCriticalSection(&g_fls_cs);
    TlsSetValue(g_fls_tls, NULL);
    HeapFree(GetProcessHeap(), 0, b);
}
