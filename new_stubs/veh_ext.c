/*
 * veh_ext.c - KernelEx-NG: vectored exception handling (AddVectoredExceptionHandler & co.) on Windows 98 SE.
 *
 * Windows 98 SE has one user-mode exception dispatcher in KERNEL32 (4.10.2222: 0xBFF87ED3), found by RE of
 * the CD's kernel32.dll:
 *   - software:  RaiseException -> 0xBFF767D3 -> 0xBFF76745 -> 0xBFF9DA0B -> dispatcher(ctx, rec, -1, 0)
 *   - hardware:  KERNEL32's ring-0 callback sets Client_EIP = dispatcher (`mov [esi+24h], imm32` on a
 *                VMM Client_Reg_Struc) and builds [fake ret][ctx][rec][..][..] on the user stack.
 * Prologue: 55 / A1 <&pCurTDB> / 8B EC  (push ebp; mov eax,[pCurTDB]; mov ebp,esp).
 * The dispatcher later calls a "continue with CONTEXT" routine (VxDCall 0x2A0015) when a debugger handled
 * the exception; we use the same routine when a vectored handler returns EXCEPTION_CONTINUE_EXECUTION.
 *
 * Hook (installed once per boot, system wide, because KERNEL32 is shared):
 *   dispatcher+0: E9 <stub> 90       (written with one cmpxchg8b: atomic on the uniprocessor 9x kernel)
 *   stub (KernelEx shared heap, permanent):
 *       push eax
 *       mov eax,[ppdbCur]; mov eax,[eax]          ; [ppdbCur] -> cell -> current PDB (two loads)
 *       mov eax,[eax+pdb_off]                      ; PDB_KEX.kex_storage (0C4h in KernelEx 4.5.2 and 4.6)
 *       test eax,eax / jz orig
 *       mov eax,[eax+slot_off]                     ; our slot (4*idx): this process's VEH entry, or 0
 *       test eax,eax / jz orig
 *       xchg eax,[esp] / ret                       ; jump to the per-process entry, eax restored
 *   orig: pop eax
 *   orig2: push ebp / mov eax,[pCurTDB] / jmp dispatcher+6
 * The fast path only does plain loads: no locks, no allocation (exceptions can happen anywhere).
 * Processes without VEH registrations (every Win98 program) take the orig path.
 *
 * Per process: kex_veh_entry (below) calls the registered handlers; EXCEPTION_CONTINUE_EXECUTION resumes
 * at the (possibly modified) CONTEXT through KERNEL32's continue routine, anything else falls through to
 * the normal 9x path (debugger, SEH frames, UnhandledExceptionFilter).
 *
 * Limits: vectored CONTINUE handlers run only after a vectored exception handler returned
 * CONTINUE_EXECUTION (NT also runs them after frame handlers do). Exceptions raised inside a vectored
 * handler skip VEH (per-thread recursion guard). Unknown KERNEL32 builds: nothing is patched,
 * AddVectoredExceptionHandler still succeeds but the handlers are never called (logged once).
 */
#include "kexnt_common.h"
#include <stddef.h>

typedef LONG (CALLBACK *VEH_FN)(PEXCEPTION_POINTERS);

typedef struct veh_node {
    struct veh_node *next, *prev;
    VEH_FN fn;
    LONG refs;
} veh_node;

static veh_node g_veh = { &g_veh, &g_veh, NULL, 0 };   /* exception handlers */
static veh_node g_vch = { &g_vch, &g_vch, NULL, 0 };   /* continue handlers */
static CRITICAL_SECTION g_veh_cs;
static DWORD g_veh_guard_tls = TLS_OUT_OF_INDEXES;
static LONG  g_veh_state;           /* 0 = not tried, 1 = active, -1 = unsupported on this KERNEL32 */
static void *g_veh_orig __attribute__((used));            /* stub "orig2": run the original dispatcher */
static void *g_k32_continue __attribute__((used));        /* KERNEL32 continue-with-context routine (stdcall, 1 arg, no return) */
static int   g_ps_index = -1;
static DWORD g_diag[8];          /* KexVehDiag: ppdb, pdb, idx, [pdb+C4], cell value after set, KERNELEX pppdbCur */

/* ---------------------------------------------------------------- helpers */
static HMODULE k32(void) { return GetModuleHandleA("KERNEL32.DLL"); }

/* KERNEL32 ordinal lookup without GetProcAddress (9x refuses ordinal lookups in KERNEL32). */
static void *k32_ordinal(WORD ord)
{
    BYTE *b = (BYTE *)k32();
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *e = (IMAGE_EXPORT_DIRECTORY *)(b +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (ord < e->Base || ord - e->Base >= e->NumberOfFunctions) return NULL;
    return b + ((DWORD *)(b + e->AddressOfFunctions))[ord - e->Base];
}

typedef DWORD (WINAPI *VXDCALL4)(DWORD svc, DWORD a, DWORD b, DWORD c, DWORD d);
static BOOL k32_writable(void *addr, DWORD size, BOOL on)
{
    VXDCALL4 vxd4 = (VXDCALL4)k32_ordinal(5);           /* VxDCall4 */
    DWORD first = (DWORD)(ULONG_PTR)addr >> 12, last = ((DWORD)(ULONG_PTR)addr + size - 1) >> 12;
    if (!vxd4) return FALSE;
    /* VMM _PageModifyPermissions(page, npages, permand, permor) - as KernelEx common/vxd.c */
    vxd4(0x0001000D, first, last - first + 1, 0, on ? 0x20060000 : 0x20040000);
    return TRUE;
}

/* Locate the dispatcher: KERNEL32 stores its address into Client_EIP ([esi+24h]).
 * Only resident code sections are scanned: _INIT is discarded after boot (its pages are gone -
 * scanning SizeOfImage page-faulted at KERNEL32+0x56000 in the 02:54 test). Every page is probed. */
static BYTE *find_dispatcher(void)
{
    BYTE *b = (BYTE *)k32();
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    DWORD size = nt->OptionalHeader.SizeOfImage;
    BYTE *found = NULL;
    int s;
    for (s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++) {
        BYTE *p, *end;
        if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE) || !memcmp(sec->Name, "_INIT", 6)) continue;
        p = b + sec->VirtualAddress;
        end = p + sec->Misc.VirtualSize;
        if (IsBadReadPtr(p, sec->Misc.VirtualSize)) continue;
        for (; p + 7 <= end; p++) {
            BYTE *t;
            if (p[0] != 0xC7 || p[1] != 0x46 || p[2] != 0x24) continue;
            t = (BYTE *)(ULONG_PTR)*(DWORD *)(p + 3);
            if (t < b || t >= b + size - 16 || IsBadReadPtr(t, 8)) continue;
            /* expected prologue: 55 A1 xx xx xx xx 8B EC   or our hook: E9 xx xx xx xx 90 8B EC */
            if (!((t[0] == 0x55 && t[1] == 0xA1) || (t[0] == 0xE9 && t[5] == 0x90)) || t[6] != 0x8B || t[7] != 0xEC)
                continue;
            if (found && found != t) return NULL;            /* ambiguous: refuse */
            found = t;
        }
    }
    return found;
}

/* "continue with CONTEXT": inside the dispatcher, `85 C0 74 08 FF 75 08 E8 rel32` (after the debugger hook). */
static void *find_continue(BYTE *disp)
{
    int i;
    for (i = 8; i < 0x80; i++) {
        BYTE *p = disp + i, *t;
        if (p[0] == 0x85 && p[1] == 0xC0 && p[2] == 0x74 && p[3] == 0x08 && p[4] == 0xFF && p[5] == 0x75 &&
            p[6] == 0x08 && p[7] == 0xE8) {
            t = p + 12 + *(LONG *)(p + 8);
            if (IsBadReadPtr(t, 14)) continue;
            /* 55 8B EC 8B 5D 08 53 6A 00 68 15 00 2A 00 : push ctx; push 0; VxDCall 0x2A0015 */
            if (t[0] == 0x55 && t[1] == 0x8B && t[2] == 0xEC && t[9] == 0x68 && *(DWORD *)(t + 10) == 0x002A0015)
                return t;
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------- shared stub */
#define STUB_MAGIC 0x3348584BUL     /* "KXH3": PDB via KERNEL32 ppdbCur, storage layout discovered at runtime */
typedef struct {
    DWORD magic;
    LONG  ps_index;
    DWORD pdb_off;                   /* offset of KernelEx's per-process storage pointer in the PDB */
    DWORD slot_off;                  /* offset of our slot inside that storage */
    DWORD ppdb;                      /* KERNEL32's "current process" global: [[ppdb]] = current PDB */
    BYTE  saved[8];                  /* original dispatcher bytes 0..7 */
    BYTE  code[64];
} veh_stub;

static int emit_stub(veh_stub *s, BYTE *disp, int *orig2_off)
{
    BYTE *c = s->code, *jz1, *jz2;
    DWORD pcur = *(DWORD *)(disp + 2);                   /* &pCurTDB from "mov eax,[imm32]" */
    if (disp[0] == 0xE9) pcur = *(DWORD *)(s->saved + 2);
    *c++ = 0x50;                                          /* push eax */
    *c++ = 0xA1; *(DWORD *)c = s->ppdb; c += 4;           /* mov eax,[ppdbCur] */
    *c++ = 0x8B; *c++ = 0x00;                             /* mov eax,[eax]  = current PDB */
    *c++ = 0x8B; *c++ = 0x80; *(DWORD *)c = s->pdb_off; c += 4;  /* mov eax,[eax+pdb_off] (storage) */
    *c++ = 0x85; *c++ = 0xC0;                             /* test eax,eax */
    *c++ = 0x74; jz1 = c++;                               /* jz orig */
    *c++ = 0x8B; *c++ = 0x80; *(DWORD *)c = s->slot_off; c += 4; /* mov eax,[eax+slot_off] (our slot) */
    *c++ = 0x85; *c++ = 0xC0;                             /* test eax,eax */
    *c++ = 0x74; jz2 = c++;                               /* jz orig */
    *c++ = 0x87; *c++ = 0x04; *c++ = 0x24;                /* xchg eax,[esp] */
    *c++ = 0xC3;                                          /* ret */
    *jz1 = (BYTE)(c - (jz1 + 1)); *jz2 = (BYTE)(c - (jz2 + 1));
    *c++ = 0x58;                                          /* orig: pop eax */
    *orig2_off = (int)(c - s->code);
    *c++ = 0x55;                                          /* orig2: push ebp */
    *c++ = 0xA1; *(DWORD *)c = pcur; c += 4;              /* mov eax,[pCurTDB] */
    *c++ = 0xE9; *(LONG *)c = (LONG)((disp + 6) - (c + 4)); c += 4; /* jmp dispatcher+6 */
    return (int)(c - s->code);
}

typedef void *(__cdecl *PS_GET)(int);
typedef int   (__cdecl *PS_SET)(int, void *);
typedef int   (__cdecl *PS_ALLOC)(void);
static PS_GET p_psget; static PS_SET p_psset;
static PS_ALLOC p_psalloc;

void kex_veh_entry(void);    /* asm, below */

/* Reserve space at the end of KERNEL32's .text the way KernelEx's VxD does (vxd/pemanip.cpp
 * AllocSectionSpace): place it after ALIGN(VirtualSize) and grow the in-memory VirtualSize, so later users
 * of the same protocol never overlap. KERNEL32 is mapped for the whole session in every process, so this
 * memory is permanent and shared - no dependency on newer KernelEx exports. Caller holds the install mutex. */
static BYTE *k32_cave(DWORD need)
{
    BYTE *b = (BYTE *)k32();
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    int i, n = nt->FileHeader.NumberOfSections;
    for (i = 0; i < n - 1; i++, sec++) {
        DWORD cur, max, k;
        BYTE *p;
        if (memcmp(sec->Name, ".text", 6)) continue;
        cur = (sec->Misc.VirtualSize + 15) & ~15UL;
        max = sec[1].VirtualAddress - sec->VirtualAddress;
        if (cur + need > max) return NULL;
        /* stay inside the page(s) the section's raw data maps (beyond it nothing is backed) */
        if (cur + need > ((sec->SizeOfRawData + 0xFFF) & ~0xFFFUL)) return NULL;
        p = b + sec->VirtualAddress + cur;
        for (k = 0; k < need; k++) if (p[k]) return NULL;      /* someone used it without telling */
        k32_writable(&sec->Misc.VirtualSize, 4, TRUE);
        if (IsBadWritePtr(&sec->Misc.VirtualSize, 4)) return NULL;
        sec->Misc.VirtualSize = cur + need;
        k32_writable(&sec->Misc.VirtualSize, 4, FALSE);
        return p;
    }
    return NULL;
}

/* KERNEL32's current-process global, as KERNEL32 itself uses it (Win98 SE 4.10.2222):
 *   SetUnhandledExceptionFilter: A1 <ppdbCur> / 8B 54 24 04 / 8B 08 / 81 C1 9C 00 00 00  (PDB->TopExcFilter)
 * KernelEx 4.5.2 reaches the PDB the same way (kexPsGetValue: [[pppdbCur]] + 0C4h). The 03:20 test showed that
 * the thread route ([[0BFFC9CE0h]] + 38h) does NOT give the PDB. */
/* KERNEL32's own export by name, read from its export table. GetProcAddress cannot be used: KernelEx answers
 * it with api-library replacements (kexnt itself provides SetUnhandledExceptionFilter since 2026-10-31 23:35,
 * which made every hook fail with -14 in the next run). */
static void *k32_export(const char *name)
{
    BYTE *b = (BYTE *)k32();
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *e = (IMAGE_EXPORT_DIRECTORY *)(b +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD *names = (DWORD *)(b + e->AddressOfNames), *funcs = (DWORD *)(b + e->AddressOfFunctions), i;
    WORD *ords = (WORD *)(b + e->AddressOfNameOrdinals);
    for (i = 0; i < e->NumberOfNames; i++)
        if (!strcmp((const char *)(b + names[i]), name)) return b + funcs[ords[i]];
    return NULL;
}

static DWORD find_ppdbcur(void)
{
    BYTE *f = (BYTE *)k32_export("SetUnhandledExceptionFilter");
    static const BYTE tail[] = { 0x8B, 0x54, 0x24, 0x04, 0x8B, 0x08, 0x81, 0xC1, 0x9C, 0x00, 0x00, 0x00 };
    if (!f || IsBadReadPtr(f, 17) || f[0] != 0xA1 || memcmp(f + 5, tail, sizeof(tail))) return 0;
    return *(DWORD *)(f + 1);
}

/* Find where KernelEx keeps this process's storage slot `idx`, using only its public API: write two
 * marker values with kexPsSetValue and look for the slot through a pointer stored in the PDB.
 * KernelEx 4.6 source: PDB_KEX.kex_storage at PDB+0xC4 -> data[idx]; 4.5 differs (test 03:20: -10).
 * Returns FALSE (and patches nothing) if no unique location is found. */
static LONG find_storage_layout(BYTE *pdb, int idx, DWORD *pdb_off, DWORD *slot_off)
{
    void *const m1 = (void *)0x4B580A11, *const m2 = (void *)0x4B580B22;
    DWORD o, k = 4 * idx, fo = 0;
    int hits = 0;
    p_psset(idx, m1);
    g_diag[1] = (DWORD)(ULONG_PTR)pdb; g_diag[2] = idx;
    if (!IsBadReadPtr(pdb + 0xC4, 4)) {
        BYTE *st = *(BYTE **)(pdb + 0xC4);
        g_diag[3] = (DWORD)(ULONG_PTR)st;
        if (st && !IsBadReadPtr(st + k, 4)) g_diag[4] = *(DWORD *)(st + k);
    }
    if (p_psget(idx) != m1) { p_psset(idx, NULL); return -12; }
    /* KernelEx 4.5.2 and 4.6: PDB_KEX.kex_storage at PDB+0C4h, data[idx] at 4*idx - try that first */
    {
        BYTE *st = IsBadReadPtr(pdb + 0xC4, 4) ? NULL : *(BYTE **)(pdb + 0xC4);
        if (st && !IsBadReadPtr(st + k, 4) && *(void **)(st + k) == m1) {
            p_psset(idx, m2);
            if (*(void **)(st + k) == m2) { p_psset(idx, NULL); *pdb_off = 0xC4; *slot_off = k; return 1; }
            p_psset(idx, m1);
        }
    }
    /* otherwise search: a PDB field (up to 100h) pointing at a block whose cell 4*idx follows the value */
    for (o = 0; o < 0x100; o += 4) {
        BYTE *st;
        if (IsBadReadPtr(pdb + o, 4)) break;
        st = *(BYTE **)(pdb + o);
        if (!st || IsBadReadPtr(st + k, 4) || *(void **)(st + k) != m1) continue;
        p_psset(idx, m2);
        if (*(void **)(st + k) == m2) { hits++; fo = o; }
        p_psset(idx, m1);
    }
    p_psset(idx, NULL);
    if (hits == 0) return -10;
    if (hits > 1) return -13;
    *pdb_off = fo; *slot_off = k;
    return 1;
}

/* Install (or find) the system-wide hook and register this process.
 * Returns 1 if VEH is live, otherwise a negative reason (reported by KexVehState):
 *  -1 KERNELEX.DLL not found        -2 kexPs* storage exports missing  -3 dispatcher not found
 *  -4 continue routine not found    -5 no space in KERNEL32 .text      -6 process storage index failed
 *  -7 patch write raced/failed       -8 existing hook not ours          -9 kexPsGetValue mismatch
 * -10 process storage slot not found  -12 kexPsSetValue/GetValue round trip failed  -13 several candidates
 * -14 KERNEL32 current-process global not found (all checked BEFORE anything is patched)
 * -11 KERNEL32 page could not be made writable */
/* KernelEx's per-process storage API (kexPs*), used by both hooks. 1 = ok, -1/-2 as below. */
/* KernelEx's core DLL. It lives in the shared arena (core/core.def BASE=0xBFA00000) and is mapped in every process,
 * but it is not in every process's module list (the boot rundll32 of KexNGBoot). Build 132: it is never loaded with
 * LoadLibrary any more - that gave the process a second reference whose DLL_PROCESS_DETACH ran KernelEx's shutdown
 * code in a process KernelEx never set up (boot-time rundll32 faulted in KERNEL32's registry code after KexNGBoot had
 * finished). Instead the image is found at its base and checked by its export name. */
static BYTE *kex_core(void)
{
    BYTE *b = (BYTE *)GetModuleHandleA("KERNELEX.DLL");
    IMAGE_NT_HEADERS *nt; IMAGE_EXPORT_DIRECTORY *e;
    if (b) return b;
    b = (BYTE *)0xBFA00000UL;
    if (IsBadReadPtr(b, 0x400) || ((IMAGE_DOS_HEADER *)b)->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    if (IsBadReadPtr(nt, sizeof(*nt)) || nt->Signature != IMAGE_NT_SIGNATURE || !nt->OptionalHeader.DataDirectory[0].VirtualAddress) return NULL;
    e = (IMAGE_EXPORT_DIRECTORY *)(b + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    if (IsBadReadPtr(e, sizeof(*e)) || IsBadReadPtr(b + e->Name, 13) || lstrcmpiA((char *)(b + e->Name), "KernelEx.dll")) return NULL;
    return b;
}
static FARPROC pe_export(BYTE *b, const char *name)
{
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *e = (IMAGE_EXPORT_DIRECTORY *)(b + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    DWORD *names = (DWORD *)(b + e->AddressOfNames), *funcs = (DWORD *)(b + e->AddressOfFunctions), i;
    WORD *ords = (WORD *)(b + e->AddressOfNameOrdinals);
    for (i = 0; i < e->NumberOfNames; i++)
        if (!lstrcmpA((const char *)(b + names[i]), name)) return (FARPROC)(b + funcs[ords[i]]);
    return NULL;
}

static LONG ps_init(void)
{
    BYTE *kx;
    if (p_psget && p_psset && p_psalloc) return 1;
    if (!(kx = kex_core())) return -1;
    p_psget = (PS_GET)pe_export(kx, "kexPsGetValue");
    p_psset = (PS_SET)pe_export(kx, "kexPsSetValue");
    p_psalloc = (PS_ALLOC)pe_export(kx, "kexPsAllocIndex");
    if (!p_psget || !p_psset || !p_psalloc) return -2;
    return 1;
}

static LONG veh_activate(void)
{
    BYTE *disp;
    veh_stub *stub = NULL;
    HANDLE mtx;
    int orig2 = 0;
    LONG why = 1;
    DWORD le = GetLastError();

    if ((why = ps_init()) != 1) return why;
    if (!(disp = find_dispatcher())) return -3;
    if (!(g_k32_continue = find_continue(disp))) return -4;

    mtx = CreateMutexA(NULL, FALSE, "KexNgVehInstall");
    if (mtx) WaitForSingleObject(mtx, INFINITE);
    if (disp[0] == 0xE9) {                                  /* already hooked by another process */
        stub = (veh_stub *)((disp + 5 + *(LONG *)(disp + 1)) - offsetof(veh_stub, code));
        if (IsBadReadPtr(stub, sizeof(*stub)) || stub->magic != STUB_MAGIC) { stub = NULL; why = -8; }
        else { veh_stub tmp; tmp = *stub; emit_stub(&tmp, disp, &orig2); }
    } else {
        int idx = p_psalloc();
        DWORD pdb_off = 0, slot_off = 0;
        DWORD ppdb = find_ppdbcur();
        g_diag[0] = ppdb;
        /* [ppdbCur] is a pointer to the cell holding the current PDB (03:51 diag: BFFC9CE4 -> C00309C4 -> PDB) */
        BYTE **cell = ppdb ? *(BYTE ***)(ULONG_PTR)ppdb : NULL;
        BYTE *pdb = (cell && !IsBadReadPtr(cell, 4)) ? *cell : NULL;
        if (idx <= 0 || idx >= 64) why = -6;
        else if (!pdb) why = -14;
        else if ((why = find_storage_layout(pdb, idx, &pdb_off, &slot_off)) != 1) { }    /* before patching */
        else if (!(stub = (veh_stub *)k32_cave((sizeof(veh_stub) + 15) & ~15UL))) why = -5;
        else {
            veh_stub tmp;
            ULONGLONG oldv, newv;
            BYTE nb[8];
            memcpy(tmp.saved, disp, 8);
            tmp.ps_index = idx; tmp.pdb_off = pdb_off; tmp.slot_off = slot_off; tmp.ppdb = ppdb;
            tmp.magic = STUB_MAGIC;
            k32_writable(stub, sizeof(*stub), TRUE);
            if (IsBadWritePtr(stub, sizeof(*stub))) { why = -11; stub = NULL; goto unlock; }
            memcpy(stub, &tmp, offsetof(veh_stub, code));    /* header incl. saved bytes (pCurTDB address) */
            emit_stub(stub, disp, &orig2);                   /* code is position dependent: emit in place */
            k32_writable(stub, sizeof(*stub), FALSE);
            nb[0] = 0xE9; *(LONG *)(nb + 1) = (LONG)(stub->code - (disp + 5)); nb[5] = 0x90;
            nb[6] = disp[6]; nb[7] = disp[7];
            memcpy(&oldv, disp, 8); memcpy(&newv, nb, 8);
            k32_writable(disp, 8, TRUE);
            if (IsBadWritePtr(disp, 8)) { why = -11; stub = NULL; goto unlock; }
            if (!__sync_bool_compare_and_swap((volatile ULONGLONG *)disp, oldv, newv)) { stub = NULL; why = -7; }
            k32_writable(disp, 8, FALSE);
        }
    }
unlock:
    if (mtx) { ReleaseMutex(mtx); CloseHandle(mtx); }
    if (!stub) { SetLastError(le); return why; }

    g_ps_index = stub->ps_index;
    g_veh_orig = stub->code + orig2;
    /* register this process and re-check through the stub's own path (same layout in every process) */
    p_psset(g_ps_index, (void *)kex_veh_entry);
    {
        BYTE *pdb = **(BYTE ***)(ULONG_PTR)stub->ppdb;
        BYTE *st = *(BYTE **)(pdb + stub->pdb_off);
        if (!st || IsBadReadPtr(st + stub->slot_off, 4) || *(void **)(st + stub->slot_off) != (void *)kex_veh_entry) {
            p_psset(g_ps_index, NULL); SetLastError(le); return -9;
        }
    }
    SetLastError(le);
    return 1;
}

/* ---------------------------------------------------------------- dispatch (per process) */
static void list_snapshot(veh_node *head, VEH_FN *out, int max, int *n)
{
    veh_node *v;
    *n = 0;
    EnterCriticalSection(&g_veh_cs);
    for (v = head->next; v != head && *n < max; v = v->next) out[(*n)++] = v->fn;
    LeaveCriticalSection(&g_veh_cs);
}

/* build 132: NT's TLS slots read straight from the TEB. The .NET 4 runtime generates code such as
 *     64 A1 64 0E 00 00          mov eax, fs:[0E64h]        ; TEB.TlsSlots[21] on NT (TlsSlots at TEB+0E10h)
 * (measured: HELLO.EXE, general protection fault at a generated stub, bytes "64 a1 64 0e 00 00"). Windows 98's
 * fs segment ends long before 0E10h; its per-thread TLS slot array is reached through fs:[2Ch] (the array
 * TlsSetValue writes - tls_ext.c). On the first fault at such an instruction it is rewritten to call a thunk
 *     mov r, fs:[2Ch] / mov r, [r + 4*index] / ret            ; no flags touched, LastError untouched
 * (E8 <thunk> + NOPs over the 6- or 7-byte original) and the thread resumes at the call. Reads only
 * (mov r32, fs:[disp32] with disp in 0E10h..0F0Fh = slots 0..63); anything else is left to the normal path. */
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */
static BYTE *g_tebfix_pool; static volatile LONG g_tebfix_used; static volatile LONG g_tebfix_n;
static int teb_tls_fix(PCONTEXT ctx, PEXCEPTION_RECORD rec)
{
    BYTE *p = (BYTE *)ctx->Eip, *t; int reg, len; DWORD disp, old; LONG at;
    if (rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || !p || IsBadReadPtr(p, 8) || p[0] != 0x64) return 0;
    if (p[1] == 0xA1) { reg = 0; disp = *(DWORD *)(p + 2); len = 6; }
    else if (p[1] == 0x8B && (p[2] & 0xC7) == 0x05) { reg = (p[2] >> 3) & 7; disp = *(DWORD *)(p + 3); len = 7; }
    else return 0;
    if (disp < 0xE10 || disp >= 0xE10 + 64 * 4 || (disp & 3) || reg == 4) return 0;
    if (!g_tebfix_pool) {
        BYTE *np = (BYTE *)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!np) return 0;
        if (InterlockedCompareExchange((LONG *)&g_tebfix_pool, (LONG)(ULONG_PTR)np, 0) != 0) VirtualFree(np, 0, MEM_RELEASE);
    }
    at = InterlockedExchangeAdd(&g_tebfix_used, 16);
    if (at + 16 > 0x10000) return 0;
    t = g_tebfix_pool + at;
    t[0] = 0x64; t[1] = 0x8B; t[2] = (BYTE)((reg << 3) | 5); *(DWORD *)(t + 3) = 0x2C;      /* mov r, fs:[2Ch] */
    t[7] = 0x8B; t[8] = (BYTE)(0x80 | (reg << 3) | reg); *(DWORD *)(t + 9) = disp - 0xE10;  /* mov r, [r + 4*index] */
    t[13] = 0xC3;                                                                            /* ret */
    if (!VirtualProtect(p, (DWORD)len, PAGE_EXECUTE_READWRITE, &old)) return 0;
    {   BYTE nb[8]; ULONGLONG ov, nv; int i;
        memcpy(nb, p, 8);
        nb[0] = 0xE8; *(LONG *)(nb + 1) = (LONG)(t - (p + 5));
        for (i = 5; i < len; i++) nb[i] = 0x90;
        memcpy(&ov, p, 8); memcpy(&nv, nb, 8);
        if (!__sync_bool_compare_and_swap((volatile ULONGLONG *)p, ov, nv)) return 0;
    }
    VirtualProtect(p, (DWORD)len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), p, (DWORD)len);
    if (InterlockedIncrement(&g_tebfix_n) <= 20) kex_crashnote("TEB TLS slot read (NT fs:[0E10h+4*i]) rewritten to Windows 98's fs:[2Ch] array (site, index, register, -)", (DWORD)(ULONG_PTR)p, (disp - 0xE10) / 4, (DWORD)reg, 0);
    return 1;                                         /* resume at the same EIP: now the call */
}
void kex_veh_ensure(void);

/* build 132: the faulting address of an access violation, as NT's exception record carries it. Windows 98 often puts
 * 0xFFFFFFFF in ExceptionInformation[1] (KEXCRASH: "reading ffffffff" for a load through a null pointer). Programs decide
 * on that address - measured: the .NET 2.0 runtime turns an access violation in managed code below 64 KB into a
 * NullReferenceException and any other into AccessViolationException, so "catch (NullReferenceException)" missed every
 * null dereference on Windows 98 and the program ended with "Application has generated an exception that could not be
 * handled". Here the address is computed from the faulting instruction's memory operand (ModRM/SIB and displacement
 * with the saved registers, string instructions, moffs forms). Segment-prefixed (fs:/gs:) and 16-bit-address forms
 * and anything not decoded keep Windows 98's value. */
static DWORD regv(PCONTEXT c, int r)
{
    switch (r & 7) { case 0: return c->Eax; case 1: return c->Ecx; case 2: return c->Edx; case 3: return c->Ebx;
                     case 4: return c->Esp; case 5: return c->Ebp; case 6: return c->Esi; default: return c->Edi; }
}
static int modrm1(BYTE op)     /* one-byte opcodes with a ModRM operand */
{
    if (op < 0x40) return (op & 7) < 4;
    return op == 0x62 || op == 0x63 || op == 0x69 || op == 0x6B || (op >= 0x80 && op <= 0x8F && op != 0x8D) ||
           op == 0xC0 || op == 0xC1 || op == 0xC4 || op == 0xC5 || op == 0xC6 || op == 0xC7 || (op >= 0xD0 && op <= 0xD3) ||
           (op >= 0xD8 && op <= 0xDF) || op == 0xF6 || op == 0xF7 || op == 0xFE || op == 0xFF;
}
static int modrm2(BYTE op)     /* 0F xx opcodes with a ModRM operand */
{
    return (op >= 0x10 && op <= 0x17) || (op >= 0x28 && op <= 0x2F) || (op >= 0x40 && op <= 0x4F) || (op >= 0x50 && op <= 0x7F) ||
           op == 0xA3 || op == 0xAB || op == 0xAF || op == 0xB0 || op == 0xB1 || op == 0xB3 || op == 0xB6 || op == 0xB7 ||
           op == 0xBA || op == 0xBB || op == 0xBC || op == 0xBD || op == 0xBE || op == 0xBF || op == 0xC0 || op == 0xC1 || op == 0xC7;
}
static void av_address(PCONTEXT c, PEXCEPTION_RECORD rec)
{
    BYTE *p = (BYTE *)c->Eip, op, m; DWORD ea; int k;
    if (rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || rec->NumberParameters < 2 || rec->ExceptionInformation[1] != 0xFFFFFFFFUL ||
        !p || IsBadReadPtr(p, 16)) return;
    for (k = 0; k < 4; k++) {                                   /* prefixes */
        if (*p == 0x64 || *p == 0x65 || *p == 0x67) return;     /* fs:/gs: or 16-bit addressing: not decoded */
        if (*p == 0xF0 || *p == 0xF2 || *p == 0xF3 || *p == 0x2E || *p == 0x36 || *p == 0x3E || *p == 0x26 || *p == 0x66) p++; else break;
    }
    op = *p++;
    if (op == 0x0F) { op = *p++; if (!modrm2(op)) return; }
    else if (op >= 0xA0 && op <= 0xA3) { rec->ExceptionInformation[1] = *(DWORD *)p; return; }
    else if (op >= 0xA4 && op <= 0xAF) {                       /* string instructions */
        if (op == 0xAA || op == 0xAB || op == 0xAE || op == 0xAF) ea = c->Edi;
        else if (op == 0xAC || op == 0xAD) ea = c->Esi;
        else ea = rec->ExceptionInformation[0] ? c->Edi : c->Esi;
        rec->ExceptionInformation[1] = ea; return;
    }
    else if (!modrm1(op)) return;
    m = *p++;
    if ((m >> 6) == 3) return;                                  /* register operand: no memory access */
    if ((m & 7) == 4) {                                         /* SIB */
        BYTE sib = *p++; int base = sib & 7, idx = (sib >> 3) & 7;
        ea = idx == 4 ? 0 : regv(c, idx) << (sib >> 6);
        if (base == 5 && (m >> 6) == 0) { ea += *(DWORD *)p; p += 4; } else ea += regv(c, base);
    } else if ((m & 7) == 5 && (m >> 6) == 0) { ea = *(DWORD *)p; p += 4; }
    else ea = regv(c, m & 7);
    if ((m >> 6) == 1) ea += (DWORD)(LONG)(signed char)*p;
    else if ((m >> 6) == 2) ea += *(DWORD *)p;
    rec->ExceptionInformation[1] = ea;
}

/* Returns 1 = continue execution with *ctx, 0 = let the 9x dispatcher continue. cdecl, called from asm. */
int __cdecl kex_veh_dispatch(PCONTEXT ctx, PEXCEPTION_RECORD rec)
{
    VEH_FN fns[64];
    EXCEPTION_POINTERS ep;
    int n, i, r = 0, bp_fix = 0;
    PVOID bp_addr = NULL;
    DWORD le = GetLastError();
    if (teb_tls_fix(ctx, rec)) { SetLastError(le); return 1; }   /* build 132: kexnt's own fix, before any handler */
    av_address(ctx, rec);                                     /* build 132: NT's faulting address for every handler */
    if (g_veh.next == &g_veh) return 0;
    if (TlsGetValue(g_veh_guard_tls)) return 0;            /* exception inside a vectored handler */
    TlsSetValue(g_veh_guard_tls, (LPVOID)1);
    ep.ExceptionRecord = rec; ep.ContextRecord = ctx;
    /* int3: Win98 reports Eip AFTER the 0xCC (test 03:54: site+1); NT reports the int3 itself (Eip and
     * ExceptionAddress = site). Handlers written for NT skip it with Eip += 1, so present NT's view and put
     * the 9x value back if nobody handles it. */
    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT && ctx->Eip && !IsBadReadPtr((BYTE *)ctx->Eip - 1, 1) &&
        *((BYTE *)ctx->Eip - 1) == 0xCC) {
        bp_fix = 1; ctx->Eip--;
        bp_addr = rec->ExceptionAddress; rec->ExceptionAddress = (PVOID)ctx->Eip;
    }
    list_snapshot(&g_veh, fns, 64, &n);
    for (i = 0; i < n; i++)
        if (fns[i](&ep) == EXCEPTION_CONTINUE_EXECUTION) { r = 1; break; }
    if (r) {
        list_snapshot(&g_vch, fns, 64, &n);
        for (i = 0; i < n; i++)
            if (fns[i](&ep) == EXCEPTION_CONTINUE_EXECUTION) break;
    }
    if (bp_fix && !r) { ctx->Eip++; rec->ExceptionAddress = bp_addr; }   /* 9x path continues unchanged */
    TlsSetValue(g_veh_guard_tls, NULL);
    SetLastError(le);
    return r;
}

/* Per-process entry, reached from the shared stub with the dispatcher's stack: [ret][ctx][rec][a3][a4]. */
__asm__(
    ".text\n.globl _kex_veh_entry\n_kex_veh_entry:\n\t"
    "pushal\n\t"
    "pushl 40(%esp)\n\t"            /* rec: 32 (pushal) + 8 */
    "pushl 40(%esp)\n\t"            /* ctx: 32 + 4 + 4 (previous push) */
    "call _kex_veh_dispatch\n\t"
    "addl $8, %esp\n\t"
    "testl %eax, %eax\n\t"
    "jnz 1f\n\t"
    "popal\n\t"
    "jmp *_g_veh_orig\n"
    "1:\n\t"
    "pushl 36(%esp)\n\t"            /* ctx */
    "call *_g_k32_continue\n\t"     /* resumes at ctx->Eip, does not return */
    "int3\n");

/* ---------------------------------------------------------------- API */
/* build 132: switch the dispatcher hook on for this process without a handler of the program (kexnt's own fixes,
 * teb_tls_fix) - .NET programs (gate_ext.c) */
void kex_veh_ensure(void)
{
    if (g_veh_state == 0) {
        LONG st = veh_activate();
        InterlockedCompareExchange(&g_veh_state, st, 0);
    }
}
static PVOID add_handler(veh_node *head, ULONG first, VEH_FN fn)
{
    veh_node *n;
    if (!fn) return NULL;
    if (head == &g_veh && g_veh_state == 0) {
        LONG st = veh_activate();
        InterlockedCompareExchange(&g_veh_state, st, 0);
        if (st < 0) OutputDebugStringA("KernelEx-NG: vectored exception handling unavailable (see KexVehState)\n");
    }
    n = (veh_node *)HeapAlloc(GetProcessHeap(), 0, sizeof(*n));
    if (!n) return NULL;
    n->fn = fn; n->refs = 1;
    EnterCriticalSection(&g_veh_cs);
    if (first) { n->next = head->next; n->prev = head; }
    else       { n->next = head; n->prev = head->prev; }
    n->next->prev = n; n->prev->next = n;
    LeaveCriticalSection(&g_veh_cs);
    return n;
}

static ULONG remove_handler(veh_node *head, PVOID h)
{
    veh_node *v;
    ULONG ok = 0;
    EnterCriticalSection(&g_veh_cs);
    for (v = head->next; v != head; v = v->next)
        if (v == h) { v->prev->next = v->next; v->next->prev = v->prev; ok = 1; break; }
    LeaveCriticalSection(&g_veh_cs);
    if (ok) HeapFree(GetProcessHeap(), 0, h);
    return ok;
}

PVOID KEXAPI kex_AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn) { return add_handler(&g_veh, first, (VEH_FN)fn); }
ULONG KEXAPI kex_RemoveVectoredExceptionHandler(PVOID h) { return remove_handler(&g_veh, h); }
PVOID KEXAPI kex_AddVectoredContinueHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn) { return add_handler(&g_vch, first, (VEH_FN)fn); }
ULONG KEXAPI kex_RemoveVectoredContinueHandler(PVOID h) { return remove_handler(&g_vch, h); }
PVOID KEXAPI kex_RtlAddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn) { return add_handler(&g_veh, first, (VEH_FN)fn); }
ULONG KEXAPI kex_RtlRemoveVectoredExceptionHandler(PVOID h) { return remove_handler(&g_veh, h); }
PVOID KEXAPI kex_RtlAddVectoredContinueHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn) { return add_handler(&g_vch, first, (VEH_FN)fn); }
ULONG KEXAPI kex_RtlRemoveVectoredContinueHandler(PVOID h) { return remove_handler(&g_vch, h); }

/* Diagnostics for kexcfg: fills 8 DWORDs (see g_diag). */
VOID KEXAPI kex_KexVehDiag(PDWORD out) { int i; if (out) for (i = 0; i < 8; i++) out[i] = g_diag[i]; }

/* Diagnostics: 1 = hook live in this process, 0 = not activated yet, <0 = reason (veh_activate). */
LONG KEXAPI kex_KexVehState(void) { return g_veh_state; }

BOOL kex_veh_init(void)
{
    InitializeCriticalSection(&g_veh_cs);
    g_veh_guard_tls = TlsAlloc();
    return g_veh_guard_tls != TLS_OUT_OF_INDEXES;
}

/* Process detach: stop routing this process's exceptions into code that is about to be unmapped. */
void kex_bigsec_detach(void);
void kex_veh_detach(void)
{
    kex_bigsec_detach();
    if (g_veh_state == 1 && p_psset && g_ps_index > 0) p_psset(g_ps_index, NULL);
    g_veh_state = 0;
}

/* ================================================================ big-file sections (2026-10-31)
 * Windows 98 SE KERNEL32 maps each section of a PE image with an internal routine (4.10.2222: 0xBFF7EA27)
 *     BOOL stdcall map_section(WORD module_index, BYTE *addr, DWORD file_offset, DWORD size, DWORD flags,
 *                              commit_fn)
 * that hands the VMM pager a 32-bit "page data" value: file page number in bits 0-15, the number of 512-byte
 * sectors of a partial last page in bits 16-18, the module index above that. File data that lies 256 MB or
 * more into the file (page number >= 0x10000) therefore cannot be described: such pages come in wrong or
 * fault. chrome.dll (275 MB, FileAlignment 0x200) has .data/.tls/.rsrc/.reloc there; the first read is the
 * loader's own resource-table walk, which fails -> ERROR_BAD_FORMAT. (Found by kextest bigimage/realimage/
 * rsrcimage/rsrcbisect + reading what the routine does; nothing of KERNEL32 is copied.)
 *
 * Fix: the routine's first bytes jump to a stub in KERNEL32's .text cave (shared, permanent):
 *       mov eax,[esp+0Ch] / and eax,7FFFFE00h / jz orig       ; file offset (bit 31 is a flag: headers)
 *       add eax,[esp+10h] / cmp eax,0FFFF000h / jbe orig       ; ends below the limit -> untouched
 *       mov eax,[ppdbCur] / mov eax,[eax] / mov eax,[eax+pdb_off] / test / jz orig
 *       mov eax,[eax+slot_off] / test / jz orig / jmp eax       ; this process's kex_bigsec_entry
 *   orig: push ebp / mov ebp,esp / sub esp,8 / jmp routine+6
 * kex_bigsec_entry (same arguments) commits the range through the original routine as demand-zero memory
 * (file offset 0, writable), then reads the section bytes from the image file (IMTE.pszFileName) with
 * ReadFile. Only processes that registered (kexnt saw them load such a DLL) take that path; every other
 * mapping in the system runs the original code after the 5 compare instructions.
 * KEXNG_NOBIGSEC=1 in the environment keeps a process unregistered (for A/B tests). */
#define BIG_MAGIC 0x3142584BUL      /* "KXB1" */
#define BIG_LIMIT 0x0FFFF000UL
typedef struct {
    DWORD magic;
    LONG  ps_index;
    DWORD pdb_off, slot_off, ppdb;
    DWORD modtab;                    /* &pModuleTableArray (from the routine's "mov eax,[imm32]") */
    BYTE  saved[8];
    BYTE  code[80];
} big_stub;

static BYTE *g_big_fn;               /* the routine */
static void *g_big_orig;             /* stub "orig": original routine (stdcall, 6 args) */
static DWORD g_big_modtab;
static LONG  g_big_state;            /* 0 not tried, 1 live, <0 reason */
static LONG  g_big_ps = -1;
static volatile LONG g_big_calls, g_big_fail;
static LONG g_big_prep;              /* last kex_bigsec_prepare verdict (diagnostics) */

typedef BOOL (WINAPI *MAPSEC)(DWORD, BYTE *, DWORD, DWORD, DWORD, void *);

static const BYTE g_big_pat[] = {   /* 55 8B EC 83 EC 08 53 56 0F BF 4D 08 57 A1 ?? ?? ?? ?? 8B 7D 14 8B 14 88
                                       81 C7 FF 01 00 00 8B 45 0C C1 EF 09 C1 E8 0C */
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x53, 0x56, 0x0F, 0xBF, 0x4D, 0x08, 0x57, 0xA1 };
static const BYTE g_big_pat2[] = { 0x8B, 0x7D, 0x14, 0x8B, 0x14, 0x88, 0x81, 0xC7, 0xFF, 0x01, 0x00, 0x00,
                                   0x8B, 0x45, 0x0C, 0xC1, 0xEF, 0x09, 0xC1, 0xE8, 0x0C };

static BYTE *find_mapsec(void)
{
    BYTE *b = (BYTE *)k32();
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    BYTE *found = NULL;
    int s;
    for (s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++) {
        BYTE *p, *end;
        if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE) || !memcmp(sec->Name, "_INIT", 6)) continue;
        p = b + sec->VirtualAddress; end = p + sec->Misc.VirtualSize;
        if (IsBadReadPtr(p, sec->Misc.VirtualSize)) continue;
        for (; p + 40 <= end; p++) {
            BOOL hooked = p[0] == 0xE9 && p[5] == 0x90;
            if (!hooked && memcmp(p, g_big_pat, sizeof(g_big_pat))) continue;
            if (hooked && memcmp(p + 6, g_big_pat + 6, sizeof(g_big_pat) - 6)) continue;
            if (memcmp(p + 18, g_big_pat2, sizeof(g_big_pat2))) continue;
            if (found && found != p) return NULL;
            found = p;
        }
    }
    return found;
}

static int emit_big(big_stub *s, BYTE *fn)
{
    BYTE *c = s->code, *j[4]; int n = 0, i;
    *c++ = 0x8B; *c++ = 0x44; *c++ = 0x24; *c++ = 0x0C;                 /* mov eax,[esp+0Ch] */
    *c++ = 0x25; *(DWORD *)c = 0x7FFFFE00; c += 4;                      /* and eax,7FFFFE00h */
    *c++ = 0x74; j[n++] = c++;                                          /* jz orig */
    *c++ = 0x03; *c++ = 0x44; *c++ = 0x24; *c++ = 0x10;                 /* add eax,[esp+10h] */
    *c++ = 0x3D; *(DWORD *)c = BIG_LIMIT; c += 4;                       /* cmp eax,limit */
    *c++ = 0x76; j[n++] = c++;                                          /* jbe orig */
    *c++ = 0xA1; *(DWORD *)c = s->ppdb; c += 4;                         /* mov eax,[ppdbCur] */
    *c++ = 0x8B; *c++ = 0x00;                                           /* mov eax,[eax] */
    *c++ = 0x8B; *c++ = 0x80; *(DWORD *)c = s->pdb_off; c += 4;         /* mov eax,[eax+pdb_off] */
    *c++ = 0x85; *c++ = 0xC0; *c++ = 0x74; j[n++] = c++;                /* test / jz orig */
    *c++ = 0x8B; *c++ = 0x80; *(DWORD *)c = s->slot_off; c += 4;        /* mov eax,[eax+slot_off] */
    *c++ = 0x85; *c++ = 0xC0; *c++ = 0x74; j[n++] = c++;                /* test / jz orig */
    *c++ = 0xFF; *c++ = 0xE0;                                           /* jmp eax */
    for (i = 0; i < n; i++) *j[i] = (BYTE)(c - (j[i] + 1));
    {   int off = (int)(c - s->code);
        *c++ = 0x55; *c++ = 0x8B; *c++ = 0xEC; *c++ = 0x83; *c++ = 0xEC; *c++ = 0x08;  /* orig prologue */
        *c++ = 0xE9; *(LONG *)c = (LONG)((fn + 6) - (c + 4)); c += 4;   /* jmp routine+6 */
        return off;
    }
}

/* Per-process path for sections whose file data reaches past 256 MB. stdcall, same args as the routine. */
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */
static void big_remember(BYTE *addr, DWORD size, DWORD characteristics);

/* Per-process path for sections whose file data reaches past 256 MB. stdcall, same args as the routine.
 * The bytes are read into a heap buffer and copied with ordinary code: the target pages can be read-only
 * (Windows' lazy resource loader commits them through a wrapper that clears the writable bit), and letting
 * ReadFile write straight into them makes the file system write to a read-only user page from ring 0 -
 * suspected cause of the 2026-11-01 00:50 blue screen (fatal exception 0D at the VxDCall gate). */
/* The section's characteristics as the image FILE has them (the section starting at file offset `off`), else `dflt`.
 * Uses `buf` (64 KB) as scratch and leaves the file pointer anywhere. */
static DWORD file_characteristics(HANDLE f, BYTE *buf, DWORD off, DWORD dflt)
{
    DWORD got = 0, lfa; IMAGE_NT_HEADERS32 *nt; IMAGE_SECTION_HEADER *sec; int i, n;
    if (SetFilePointer(f, 0, NULL, FILE_BEGIN) == 0xFFFFFFFF || !ReadFile(f, buf, 0x1000, &got, NULL) || got < 0x200) return dflt;
    lfa = ((IMAGE_DOS_HEADER *)buf)->e_lfanew;
    if (lfa > 0xC00) return dflt;
    nt = (IMAGE_NT_HEADERS32 *)(buf + lfa);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return dflt;
    sec = IMAGE_FIRST_SECTION(nt); n = nt->FileHeader.NumberOfSections;
    for (i = 0; i < n && (BYTE *)(sec + i + 1) <= buf + got; i++)
        if (sec[i].PointerToRawData == off) return sec[i].Characteristics;
    return dflt;
}

static BOOL WINAPI kex_bigsec_entry(DWORD modidx, BYTE *addr, DWORD fileoff, DWORD size, DWORD flags, void *commit)
{
    BYTE **tab, *imte, *buf; const char *name; HANDLE f; DWORD done, le = GetLastError(), pos, old = 0;
    BOOL ok = TRUE, prot = FALSE;
    InterlockedIncrement(&g_big_calls);
    kex_trace("bigsec", (DWORD)(ULONG_PTR)addr, fileoff, size, flags);
    /* 1. pages as demand-zero memory, writable if the caller's commit honours it */
    if (!((MAPSEC)g_big_orig)(modidx, addr, 0, size, flags | 0x80000000, commit)) { kex_trace("bigsec commit FAILED", 0, 0, 0, 0); return FALSE; }
    /* 2. the bytes, from the image file */
    tab = *(BYTE ***)(ULONG_PTR)g_big_modtab;
    imte = tab ? tab[(SHORT)(WORD)modidx] : NULL;
    name = (imte && !IsBadReadPtr(imte + 0x0C, 4)) ? *(const char **)(imte + 0x0C) : NULL;
    if (!name || IsBadStringPtrA(name, MAX_PATH)) { InterlockedIncrement(&g_big_fail); SetLastError(le); return FALSE; }
    f = CreateFileA(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { InterlockedIncrement(&g_big_fail); SetLastError(le); big_remember(addr, size, flags); return FALSE; }
    if (!(buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, 0x10000))) { CloseHandle(f); InterlockedIncrement(&g_big_fail); SetLastError(le); big_remember(addr, size, flags); return FALSE; }
    big_remember(addr, size, file_characteristics(f, buf, fileoff & 0x7FFFFFFFUL, flags));   /* the header copy may say writable (big_private_sections) */
    if (IsBadWritePtr(addr, size ? 1 : 0) || (size && IsBadWritePtr(addr + size - 1, 1)))
        prot = VirtualProtect(addr, size, PAGE_READWRITE, &old);
    if (SetFilePointer(f, (LONG)(fileoff & 0x7FFFFFFF), NULL, FILE_BEGIN) == 0xFFFFFFFF) ok = FALSE;
    for (pos = 0; ok && pos < size; pos += done) {
        DWORD want = size - pos < 0x10000 ? size - pos : 0x10000;
        done = 0;
        if (!ReadFile(f, buf, want, &done, NULL)) { ok = FALSE; break; }
        if (!done) break;                       /* file shorter than the header says: the rest stays zero */
        if (IsBadWritePtr(addr + pos, done)) { ok = FALSE; break; }
        memcpy(addr + pos, buf, done);
    }
    if (prot) VirtualProtect(addr, size, old, &old);
    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(f);
    if (!ok) InterlockedIncrement(&g_big_fail);
    kex_trace(ok ? "bigsec ok" : "bigsec READ FAILED", (DWORD)(ULONG_PTR)addr, pos, prot, old);
    SetLastError(le);
    return ok;
}

static BOOL big_disabled(void)
{
    char v[8];
    return GetEnvironmentVariableA("KEXNG_NOBIGSEC", v, sizeof(v)) && v[0] == '1';
}

/* Install (or join) a KERNEL32 hook of `fn` whose stub is built by `emit` and register `entry` as this
 * process's target. Shared by the big-file section hook and the DLL-entry hook. Returns 1 or a reason. */
typedef int (*EMIT_FN)(big_stub *, BYTE *);
static LONG hook_activate(BYTE *fn, DWORD magic, EMIT_FN emit, void *entry, big_stub **out, int *orig_off)
{
    big_stub *stub = NULL; HANDLE mtx; int orig = 0; LONG why = 1; DWORD le = GetLastError();
    if ((why = ps_init()) != 1) return why;
    mtx = CreateMutexA(NULL, FALSE, "KexNgVehInstall");
    if (mtx) WaitForSingleObject(mtx, INFINITE);
    if (fn[0] == 0xE9) {                                    /* already hooked by another process */
        stub = (big_stub *)((fn + 5 + *(LONG *)(fn + 1)) - offsetof(big_stub, code));
        if (IsBadReadPtr(stub, sizeof(*stub)) || stub->magic != magic) { stub = NULL; why = -8; }
        else { big_stub tmp = *stub; orig = emit(&tmp, fn); }
    } else {
        int idx = p_psalloc();
        DWORD pdb_off = 0, slot_off = 0, ppdb = find_ppdbcur();
        BYTE **cell = ppdb ? *(BYTE ***)(ULONG_PTR)ppdb : NULL;
        BYTE *pdb = (cell && !IsBadReadPtr(cell, 4)) ? *cell : NULL;
        if (idx <= 0 || idx >= 64) why = -6;
        else if (!pdb) why = -14;
        else if ((why = find_storage_layout(pdb, idx, &pdb_off, &slot_off)) != 1) { }
        else if (!(stub = (big_stub *)k32_cave((sizeof(big_stub) + 15) & ~15UL))) why = -5;
        else {
            big_stub tmp; ULONGLONG oldv, newv; BYTE nb[8];
            memset(&tmp, 0, sizeof(tmp));
            memcpy(tmp.saved, fn, 8);
            tmp.magic = magic; tmp.ps_index = idx; tmp.pdb_off = pdb_off; tmp.slot_off = slot_off;
            tmp.ppdb = ppdb; tmp.modtab = g_big_modtab;
            k32_writable(stub, sizeof(*stub), TRUE);
            if (IsBadWritePtr(stub, sizeof(*stub))) { why = -11; stub = NULL; goto unlock; }
            memcpy(stub, &tmp, offsetof(big_stub, code));
            orig = emit(stub, fn);
            k32_writable(stub, sizeof(*stub), FALSE);
            nb[0] = 0xE9; *(LONG *)(nb + 1) = (LONG)(stub->code - (fn + 5)); nb[5] = 0x90; nb[6] = fn[6]; nb[7] = fn[7];
            memcpy(&oldv, fn, 8); memcpy(&newv, nb, 8);
            k32_writable(fn, 8, TRUE);
            if (IsBadWritePtr(fn, 8)) { why = -11; stub = NULL; goto unlock; }
            if (!__sync_bool_compare_and_swap((volatile ULONGLONG *)fn, oldv, newv)) { stub = NULL; why = -7; }
            k32_writable(fn, 8, FALSE);
        }
    }
unlock:
    if (mtx) { ReleaseMutex(mtx); CloseHandle(mtx); }
    if (!stub) { SetLastError(le); return why; }
    p_psset(stub->ps_index, entry);
    {
        BYTE *pdb = **(BYTE ***)(ULONG_PTR)stub->ppdb;
        BYTE *st = *(BYTE **)(pdb + stub->pdb_off);
        if (!st || IsBadReadPtr(st + stub->slot_off, 4) || *(void **)(st + stub->slot_off) != entry) {
            p_psset(stub->ps_index, NULL); SetLastError(le); return -9;
        }
    }
    *out = stub; *orig_off = orig;
    SetLastError(le);
    return 1;
}

static LONG big_activate(void)
{
    BYTE *fn; big_stub *stub; int orig; LONG why;
    if (big_disabled()) return -20;
    if (!(fn = find_mapsec())) return -3;
    g_big_modtab = *(DWORD *)(fn + 14);
    if ((why = hook_activate(fn, BIG_MAGIC, emit_big, (void *)kex_bigsec_entry, &stub, &orig)) != 1) return why;
    g_big_fn = fn; g_big_ps = stub->ps_index; g_big_orig = stub->code + orig;
    return 1;
}

/* ================================================================ DLL entry hook (2026-10-31)
 * KERNEL32 calls every DLL entry point through one routine (4.10.2222: 0xBFF7DD32):
 *     BOOL stdcall call_dll_entry(MODREF *mr, DWORD reason, LPVOID reserved)
 * (module = pModuleTableArray[(SHORT)mr->+10h] -> IMTE, IMTE+4 -> its NT headers copy, ImageBase = actual base;
 * checks IMAGE_FILE_DLL, AddressOfEntryPoint). NT sets up a DLL's static TLS and runs its TLS callbacks before the
 * entry point; Windows 98 does neither for DLLs loaded with LoadLibrary. tls_ext.c used to do it after
 * LoadLibrary returned - too late for chrome.dll, whose CRT start-up already uses thread_local.
 * Hook: prologue `64 A1 00 00 00 00` (mov eax,fs:[0]) -> stub:
 *       cmp dword [esp+8],1 / jne orig                         ; DLL_PROCESS_ATTACH only
 *       per-process slot lookup as above / jmp eax              ; kex_dllentry_entry
 *   orig: mov eax,fs:[0] / jmp routine+6
 * kex_dllentry_entry sets up TLS (tls_ext.c kex_tls_early) when the load came through kexnt's LoadLibrary on
 * this thread, then continues into the original routine. Modules Windows loads at process start (TLS already
 * set up by Windows) are never touched. */
#define ENT_MAGIC 0x3145584BUL      /* "KXE1" */
static BYTE *g_ent_fn;
static void *g_ent_orig;
static LONG  g_ent_state;
static LONG  g_ent_ps = -1;
static volatile LONG g_ent_calls;

static const BYTE g_ent_pat[] = { 0x64, 0xA1, 0, 0, 0, 0, 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68 };
static const BYTE g_ent_pat2[] = { 0x50, 0x8B, 0x4D, 0x08, 0x64, 0x89, 0x25, 0, 0, 0, 0, 0x8B, 0x15 };   /* +21 */
static const BYTE g_ent_pat3[] = { 0x81, 0xEC, 0x8C, 0x01, 0x00, 0x00, 0x0F, 0xBF, 0x41, 0x10, 0x53, 0x56, 0x57,
                                   0x8B, 0x1C, 0x82, 0xA1 };                                               /* +38 */
static const BYTE g_ent_pat4[] = { 0x89, 0x65, 0xE8, 0x8B, 0x53, 0x04, 0x8B, 0x18, 0xF6, 0x42, 0x17, 0x20 };  /* +59 */

static BYTE *find_dllentry(void)
{
    BYTE *b = (BYTE *)k32();
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    BYTE *found = NULL;
    int s;
    for (s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++) {
        BYTE *p, *end;
        if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE) || !memcmp(sec->Name, "_INIT", 6)) continue;
        p = b + sec->VirtualAddress; end = p + sec->Misc.VirtualSize;
        if (IsBadReadPtr(p, sec->Misc.VirtualSize)) continue;
        for (; p + 72 <= end; p++) {
            BOOL hooked = p[0] == 0xE9 && p[5] == 0x90;
            if (!hooked && memcmp(p, g_ent_pat, sizeof(g_ent_pat))) continue;
            if (hooked && memcmp(p + 6, g_ent_pat + 6, sizeof(g_ent_pat) - 6)) continue;
            if (memcmp(p + 21, g_ent_pat2, sizeof(g_ent_pat2)) || memcmp(p + 38, g_ent_pat3, sizeof(g_ent_pat3)) ||
                memcmp(p + 59, g_ent_pat4, sizeof(g_ent_pat4))) continue;
            if (found && found != p) return NULL;
            found = p;
        }
    }
    return found;
}

static int emit_ent(big_stub *s, BYTE *fn)
{
    BYTE *c = s->code, *j[4]; int n = 0, i, off;
    *c++ = 0x83; *c++ = 0x7C; *c++ = 0x24; *c++ = 0x08; *c++ = 0x01;   /* cmp dword [esp+8],1 */
    *c++ = 0x75; j[n++] = c++;                                          /* jne orig */
    *c++ = 0xA1; *(DWORD *)c = s->ppdb; c += 4;                         /* mov eax,[ppdbCur] */
    *c++ = 0x8B; *c++ = 0x00;                                           /* mov eax,[eax] */
    *c++ = 0x8B; *c++ = 0x80; *(DWORD *)c = s->pdb_off; c += 4;         /* mov eax,[eax+pdb_off] */
    *c++ = 0x85; *c++ = 0xC0; *c++ = 0x74; j[n++] = c++;                /* test / jz orig */
    *c++ = 0x8B; *c++ = 0x80; *(DWORD *)c = s->slot_off; c += 4;        /* mov eax,[eax+slot_off] */
    *c++ = 0x85; *c++ = 0xC0; *c++ = 0x74; j[n++] = c++;                /* test / jz orig */
    *c++ = 0xFF; *c++ = 0xE0;                                           /* jmp eax */
    for (i = 0; i < n; i++) *j[i] = (BYTE)(c - (j[i] + 1));
    off = (int)(c - s->code);
    *c++ = 0x64; *c++ = 0xA1; *(DWORD *)c = 0; c += 4;                  /* mov eax,fs:[0] */
    *c++ = 0xE9; *(LONG *)c = (LONG)((fn + 6) - (c + 4)); c += 4;       /* jmp routine+6 */
    return off;
}

void kex_tls_early(HMODULE h);       /* tls_ext.c */
void kex_reloc_check(HMODULE h, const char *path);   /* reloc_ext.c */
BOOL kex_tls_in_load(void);

typedef BOOL (WINAPI *DLLENTRY)(void *, DWORD, LPVOID);
void kex_probe_big_image(HMODULE h);   /* loader_ext.c */
/* ---- native TLS slot reserve for Windows' own DLLs (2026-11-02).
 * Windows 98 has 80 TLS slots per process. KernelEx's TlsAlloc (kexbasen TlsExt.c) hands programs the 79
 * native slots first and only then its extended ones - but a DLL from the SYSTEM folder imports the native
 * TlsAlloc, which knows nothing of the extended slots. Mypal uses up all 79; afterwards Winsock 2 could not
 * load its name-space provider RNR20.DLL (its DllMain needs a slot) and every name lookup failed with
 * WSAHOST_NOT_FOUND in 2 ms. kexnt now holds a few native slots from its own start-up and gives them back
 * just for the DllMain of a SYSTEM-folder DLL (DLL-entry hook), taking whatever is left back afterwards. */
#define TLS_RES_MAX 8
static DWORD g_res[TLS_RES_MAX]; static LONG g_res_n = -1, g_res_depth; static char g_sysdir[MAX_PATH]; static int g_sysdir_len;

void kex_tls_reserve_init(void)
{
    int i, n = 0;
    g_sysdir_len = (int)GetSystemDirectoryA(g_sysdir, sizeof(g_sysdir) - 2);
    if (g_sysdir_len <= 0 || g_sysdir_len >= MAX_PATH - 2) { g_sysdir_len = 0; return; }
    if (g_sysdir[g_sysdir_len - 1] != '\\') { g_sysdir[g_sysdir_len++] = '\\'; g_sysdir[g_sysdir_len] = 0; }
    for (i = 0; i < TLS_RES_MAX; i++) { DWORD t = TlsAlloc(); if (t == TLS_OUT_OF_INDEXES) break; g_res[n++] = t; }
    g_res_n = n;
}

/* Programs' TlsAlloc (2026-11-02, second half of the RNR20 story): KernelEx's TlsAlloc_new hands out native slots
 * while any are free, so a big program soon holds all 79 and every SYSTEM-folder DLL loaded later fails its
 * DllMain (the trace showed RNR20.DLL loaded and thrown away 22 times; the reserve itself had been drained to 0
 * during start-up). kexnt's TlsAlloc for programs now hides the free native slots for the duration of the call,
 * so KernelEx gives the program one of its 1024 extended slots instead and the native ones stay for Windows' own
 * DLLs. The slots briefly held are taken back into kexnt's reserve (up to TLS_RES_MAX) first. */
FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */
static LONG g_tlsalloc_lock;
DWORD KEXAPI kex_TlsAlloc(void)
{
    static FARPROC prev;
    DWORD held[80], r; int n = 0, i;
    if (!prev) prev = kex_prev_impl("KERNEL32.DLL", "TlsAlloc");
    if (!prev) return TlsAlloc();
    kex_spin_acquire((volatile LONG *)&g_tlsalloc_lock);
    while (n < 80) { DWORD t = TlsAlloc(); if (t == TLS_OUT_OF_INDEXES) break; held[n++] = t; }
    r = ((DWORD (WINAPI *)(void))prev)();
    if (r == TLS_OUT_OF_INDEXES && n) r = held[--n];   /* no extended slot left: give the program a native one */
    for (i = 0; i < n; i++) {
        if (g_res_n >= 0 && g_res_n < TLS_RES_MAX && !g_res_depth) g_res[g_res_n++] = held[i];   /* top up the reserve */
        else TlsFree(held[i]);
    }
    InterlockedExchange(&g_tlsalloc_lock, 0);
    return r;
}

/* build 46: a slot for a DLL's STATIC TLS (tls_ext.c). Compiled code reads it as fs:[2Ch][index] - Windows 98's
 * 80-entry slot array - so it must be a native slot: KernelEx's extended ones (80 and up, what kex_TlsAlloc and
 * KernelEx's TlsAlloc_new hand out) live elsewhere. KERNEL32's own TlsAlloc first, then kexnt's reserve. */
DWORD kex_tls_native_alloc(void)
{
    typedef DWORD (WINAPI *T_TA)(void);
    static T_TA f; DWORD r;
    if (!f) f = (T_TA)k32_export("TlsAlloc");
    r = f ? f() : TLS_OUT_OF_INDEXES;
    if (r == TLS_OUT_OF_INDEXES) {
        kex_spin_acquire((volatile LONG *)&g_tlsalloc_lock);
        if (g_res_n > 0) r = g_res[--g_res_n];
        InterlockedExchange(&g_tlsalloc_lock, 0);
    }
    return r < 80 ? r : TLS_OUT_OF_INDEXES;
}

static void res_release(void)
{
    LONG i, n = g_res_n;
    if (n <= 0) return;
    g_res_n = 0;
    for (i = 0; i < n; i++) TlsFree(g_res[i]);
}

static void res_refill(void)
{
    int n = 0; DWORD le = GetLastError();
    while (n < TLS_RES_MAX) { DWORD t = TlsAlloc(); if (t == TLS_OUT_OF_INDEXES) break; g_res[n++] = t; }
    g_res_n = n;
    SetLastError(le);
}

static const char *entry_path(void *mr)
{
    BYTE **tab, *imte; const char *path;
    if (!g_big_modtab || !mr) return NULL;
    tab = *(BYTE ***)(ULONG_PTR)g_big_modtab;
    imte = tab ? tab[*(SHORT *)((BYTE *)mr + 0x10)] : NULL;
    if (!imte || IsBadReadPtr(imte + 0x0C, 4)) return NULL;
    path = *(const char **)(imte + 0x0C);
    return path && !IsBadStringPtrA(path, MAX_PATH) ? path : NULL;
}

static BOOL has_dotdot(const char *p)
{
    for (; *p; p++) if (p[0] == '\\' && p[1] == '.' && p[2] == '.' && p[3] == '\\') return TRUE;
    return FALSE;
}
static BOOL is_sysdir_dll(const char *path)
{
    const char *f; char full[MAX_PATH], *fp;
    /* build 131: KernelEx's KnownDLLs entries are relative to the KERNELEX folder ("..\SYSTEM\DWrite.dll"), so
     * Windows 98 names such a module C:\WINDOWS\KERNELEX\..\SYSTEM\DWRITE.DLL - still a SYSTEM DLL */
    if (path && has_dotdot(path) && lstrlenA(path) < MAX_PATH && GetFullPathNameA(path, MAX_PATH, full, &fp)) path = full;
    if (!path || !g_sysdir_len || CompareStringA(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, path, g_sysdir_len, g_sysdir, g_sysdir_len) != CSTR_EQUAL) return FALSE;
    for (f = path + g_sysdir_len; *f; f++) if (*f == '\\') return FALSE;   /* directly in SYSTEM, not below */
    return TRUE;
}

/* 2026-11-02 build 11: Windows 98 maps the READ-ONLY sections of a module once for every process that loads it
 * (a second process does not even call the section mapper for them, only for writable ones) and has no
 * copy-on-write. For a big image those pages are the demand-zero copies kex_bigsec_entry made in the FIRST
 * process, so anything that process writes after VirtualProtect - Chromium's import-table patches
 * (sandbox_win.cc:902 CHECKs its DuplicateHandle patch; base/debug/handle_hooks_win.cc) - appears in every other
 * process, whose saved "original" then is wrong or NULL (renderers/utilities called address 0, build 10).
 * The loader decides per section from the header copy in the module table entry (IMTE+4, shared memory); marking
 * the big read-only sections writable there makes every later process map them itself, through
 * kex_bigsec_entry, as private pages. What VirtualQuery reports still comes from the file's real header. */
static BOOL rdata_private(void)
{
    char v[8];
    return GetEnvironmentVariableA("KEXNG_PRIVRDATA", v, sizeof(v)) && v[0] == '1';
}
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */
/* build 77: the big image's .rdata when it is shared between processes (kex_bigsec_protect) */
static DWORD g_rd_lo, g_rd_hi;
static void big_shared_rdata(IMAGE_NT_HEADERS32 *nt, DWORD base)
{
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt); int i, n = nt->FileHeader.NumberOfSections;
    if (rdata_private() || n <= 0 || n > 96 || IsBadReadPtr(sec, n * sizeof(*sec))) return;
    for (i = 0; i < n; i++)
        if (!memcmp(sec[i].Name, ".rdata", 7) && sec[i].Misc.VirtualSize) {
            g_rd_lo = base + sec[i].VirtualAddress;
            g_rd_hi = g_rd_lo + ((sec[i].Misc.VirtualSize + 0xFFF) & ~0xFFFUL);
        }
}
static void big_private_sections(IMAGE_NT_HEADERS32 *nt)
{
    IMAGE_SECTION_HEADER *sec; int i, n, changed = 0;
    if ((DWORD)(ULONG_PTR)nt < 0x80000000UL) return;              /* not the shared copy: leave it */
    sec = IMAGE_FIRST_SECTION(nt); n = nt->FileHeader.NumberOfSections;
    if (n <= 0 || n > 96 || IsBadWritePtr(sec, n * sizeof(*sec))) { kex_trace("bigsec: header copy not writable", (DWORD)(ULONG_PTR)nt, 0, 0, 0); return; }
    for (i = 0; i < n; i++) {
        if (!sec[i].SizeOfRawData || (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
        /* build 16: each private copy costs its full size in EVERY Chrome process (chrome.dll: .rdata 30 MB,
         * .reloc 10 MB, ...). Only sections a process may write need it: .reloc (discardable, read by the loader
         * only) and .rsrc stay shared. .rdata holds the import table that Chromium patches, so it stays private. */
        if ((sec[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) || !memcmp(sec[i].Name, ".rsrc", 6)) continue;
        /* build 77: .rdata stays shared too (30 MB of chrome.dll, copied and read from disk again in EVERY helper
         * process - renderers took seconds to start on a 1 GB machine and the system sat at 1 MB free). The only
         * writes into it are import-table patches; kex_bigsec_protect undoes those when the program puts the
         * protection back (see g_rd_*). KEXNG_PRIVRDATA=1 in the environment = the old private copies. */
        if (!memcmp(sec[i].Name, ".rdata", 7) && !rdata_private()) continue;
        if ((sec[i].PointerToRawData & 0x7FFFFE00UL) + sec[i].SizeOfRawData <= BIG_LIMIT) continue;   /* mapped normally */
        sec[i].Characteristics |= IMAGE_SCN_MEM_WRITE; changed++;
    }
    kex_trace("bigsec: read-only sections made per-process", (DWORD)(ULONG_PTR)nt, (DWORD)changed, (DWORD)n, 0);
}

/* Diagnostics: are the image's imports bound in this process? (first entry of each of the first descriptors) */
static void big_check_iat(BYTE *base)
{
    IMAGE_NT_HEADERS32 *nt; IMAGE_IMPORT_DESCRIPTOR *d; DWORD rva, bound = 0, raw = 0; int i;
    if (IsBadReadPtr(base, 0x40)) return;
    nt = (IMAGE_NT_HEADERS32 *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    if (IsBadReadPtr(nt, sizeof(*nt))) return;
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva) return;
    d = (IMAGE_IMPORT_DESCRIPTOR *)(base + rva);
    for (i = 0; i < 8 && !IsBadReadPtr(d + i, sizeof(*d)) && d[i].Name; i++) {
        DWORD *iat = (DWORD *)(base + d[i].FirstThunk), *intt = (DWORD *)(base + (d[i].OriginalFirstThunk ? d[i].OriginalFirstThunk : d[i].FirstThunk));
        if (IsBadReadPtr(iat, 4) || IsBadReadPtr(intt, 4)) continue;
        if (iat[0] == intt[0] && d[i].OriginalFirstThunk) raw++; else bound++;
    }
    kex_trace(raw ? "bigsec: import table NOT bound in this process" : "bigsec: import table bound", (DWORD)(ULONG_PTR)base, bound, raw, 0);
    /* build 77: with a shared .rdata every process uses the import table the FIRST process bound. Each entry must
     * point into a module that is loaded at that place in THIS process too (DWRITE.DLL is relocated - it has been at
     * 01620000 in every Chrome process so far). Checked for every entry; a bad one goes to KEXCRASH. */
    if (g_rd_lo) {
        DWORD bad = 0, first_bad = 0, first_slot = 0, total = 0;
        for (i = 0; !IsBadReadPtr(d + i, sizeof(*d)) && d[i].Name && i < 64; i++) {
            DWORD *iat = (DWORD *)(base + d[i].FirstThunk); int k;
            for (k = 0; k < 4096 && !IsBadReadPtr(iat + k, 4) && iat[k]; k++) {
                MEMORY_BASIC_INFORMATION mb; DWORD v = iat[k];
                total++;
                if (v >= 0x80000000UL) continue;                       /* shared arena: the same in every process */
                if (VirtualQuery((void *)(ULONG_PTR)v, &mb, sizeof(mb)) && mb.State == MEM_COMMIT && mb.AllocationBase &&
                    !IsBadReadPtr(mb.AllocationBase, 2) && *(WORD *)mb.AllocationBase == IMAGE_DOS_SIGNATURE) continue;
                if (!bad++) { first_bad = v; first_slot = (DWORD)(ULONG_PTR)(iat + k); }
            }
        }
        if (bad) kex_crashnote("shared .rdata: import-table entries point to no module in THIS process - run with KEXNG_PRIVRDATA=1 (bad, total, first value, its slot)",
                               bad, total, first_bad, first_slot);
    }
}

static BOOL WINAPI entry_inner(void *mr, DWORD reason, LPVOID reserved);
static BOOL WINAPI kex_dllentry_entry(void *mr, DWORD reason, LPVOID reserved)
{
    BOOL r, rel = FALSE;
    if (reason == DLL_PROCESS_ATTACH && g_res_n >= 0) {
        DWORD le = GetLastError(); const char *path = entry_path(mr);
        if (is_sysdir_dll(path) && InterlockedIncrement(&g_res_depth) == 1) {
            LONG had = g_res_n;
            rel = TRUE; res_release();
            if (had) kex_trace("tls reserve: slots lent to", had, 0, 0, 0), kex_trace(path, 0, 0, 0, 0);
        } else if (is_sysdir_dll(path)) InterlockedIncrement(&g_res_depth), rel = 2;
        SetLastError(le);
    }
    if (reason == DLL_PROCESS_ATTACH) {     /* build 55: OPENGL32's USER32/GDI32 calls through the guard, before its DllMain */
        void kex_guard_imports_if_gl(HMODULE mod, const char *path);
        DWORD le = GetLastError(); const char *path = entry_path(mr);
        if (path && is_sysdir_dll(path)) {
            const char *s, *bn = path;
            for (s = path; *s; s++) if (*s == '\\') bn = s + 1;
            if ((bn[0] | 32) == 'o' || (bn[0] | 32) == 'g') kex_guard_imports_if_gl(GetModuleHandleA(path), path);
        }
        SetLastError(le);
    }
    if (reason == DLL_PROCESS_ATTACH) {   /* build 131: NT 6+ code patched (PEB reads) BEFORE its own DllMain runs. The api-ms
                                           * shells only do it in their DllMain, and a DLL that imports none of them
                                           * (Supermium's pwrp_k32.dll) ran its DllMain unpatched and read the 9x PDB */
        VOID KEXAPI kex_KexPatchNtModules(void);
        const char *path = entry_path(mr);
        if (path && !is_sysdir_dll(path)) kex_KexPatchNtModules();
    }
    r = entry_inner(mr, reason, reserved);
    if (rel) { if (InterlockedDecrement(&g_res_depth) == 0) res_refill(); }
    if (reason == DLL_PROCESS_ATTACH) {   /* Windows' own DLLs starting up (RNR20 hunt, 2026-11-02): which, and did DllMain agree */
        static LONG n_sys;
        const char *path = entry_path(mr);
        if (is_sysdir_dll(path) && InterlockedIncrement(&n_sys) <= 200) {
            DWORD le = GetLastError();
            kex_trace(r ? "sysdll DllMain ok" : "sysdll DllMain FAILED", (DWORD)r, (DWORD)g_res_n, 0, 0);
            kex_trace(path, 0, 0, 0, 0);
            SetLastError(le);
        }
    }
    return r;
}

static BOOL WINAPI entry_inner(void *mr, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH && mr && kex_tls_in_load() && g_big_modtab) {
        BYTE **tab = *(BYTE ***)(ULONG_PTR)g_big_modtab, *imte;
        DWORD le = GetLastError();
        imte = tab ? tab[*(SHORT *)((BYTE *)mr + 0x10)] : NULL;
        if (imte && !IsBadReadPtr(imte + 4, 4)) {
            IMAGE_NT_HEADERS32 *nt = *(IMAGE_NT_HEADERS32 **)(imte + 4);
            if (nt && !IsBadReadPtr(nt, sizeof(*nt))) {
                const char *path = !IsBadReadPtr(imte + 0x0C, 4) ? *(const char **)(imte + 0x0C) : NULL;
                InterlockedIncrement(&g_ent_calls);
                kex_trace(path && !IsBadStringPtrA(path, MAX_PATH) ? path : "dllentry ?", nt->OptionalHeader.ImageBase, 0, 0, 0);
                if (path && !IsBadStringPtrA(path, MAX_PATH))     /* relocations first: TLS copies data */
                    kex_reloc_check((HMODULE)(ULONG_PTR)nt->OptionalHeader.ImageBase, path);
                kex_tls_early((HMODULE)(ULONG_PTR)nt->OptionalHeader.ImageBase);
                if (nt->OptionalHeader.SizeOfImage > 0x0FFFF000UL) {   /* Chrome hunt: big images only */
                    BOOL r;
                    /* the WHOLE image, not only the sections our hook mapped: Windows 98's VirtualProtect
                     * blue-screens on any page of such an image (kex_VirtualProtect then uses kex_bigsec_protect) */
                    big_remember((BYTE *)(ULONG_PTR)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage, 0xFFFFFFFFUL);
                    big_private_sections(nt);
                    big_shared_rdata(nt, nt->OptionalHeader.ImageBase);
                    big_check_iat((BYTE *)(ULONG_PTR)nt->OptionalHeader.ImageBase);
                    kex_trace("dllentry: calling DllMain", nt->OptionalHeader.ImageBase, 0, 0, 0);
                    SetLastError(le);
                    r = ((DLLENTRY)g_ent_orig)(mr, reason, reserved);
                    kex_trace("dllentry: DllMain returned", nt->OptionalHeader.ImageBase, r, 0, 0);
                    return r;
                }
            }
        }
        SetLastError(le);
    }
    return ((DLLENTRY)g_ent_orig)(mr, reason, reserved);
}

static LONG ent_activate(void)
{
    BYTE *fn, *mapsec; big_stub *stub; int orig; LONG why;
    char v[8];
    if (GetEnvironmentVariableA("KEXNG_NOTLSENTRY", v, sizeof(v)) && v[0] == '1') return -20;
    if (!(fn = find_dllentry())) return -3;
    if (!g_big_modtab) {     /* pModuleTableArray: the same global both routines read */
        if (!(mapsec = find_mapsec())) return -15;
        g_big_modtab = *(DWORD *)(mapsec + 14);
    }
    if (*(DWORD *)(fn + 34) != g_big_modtab) return -16;
    if ((why = hook_activate(fn, ENT_MAGIC, emit_ent, (void *)kex_dllentry_entry, &stub, &orig)) != 1) return why;
    g_ent_fn = fn; g_ent_ps = stub->ps_index; g_ent_orig = stub->code + orig;
    return 1;
}

LONG KEXAPI kex_KexTlsEntryState(PDWORD calls)
{
    if (calls) *calls = (DWORD)g_ent_calls;
    return g_ent_state;
}

static void ent_prepare(void)
{
    if (g_ent_state == 0) {
        LONG st = ent_activate();
        InterlockedCompareExchange(&g_ent_state, st, 0);
        if (st < 0) OutputDebugStringA("KernelEx-NG: DLL entry hook unavailable (see KexTlsEntryState)\n");
    }
}

/* build 132: peb_ext.c, whenever it patches this process's NT 6+ modules: from then on every DLL loaded later is
 * prepared before its DllMain (PEB patch) by the DLL-entry hook - also in a Windows 98 program, where nothing loads
 * through kexnt's LoadLibrary (Windows Media Player: DirectShow loads K-Lite's LAVVideo.ax through OLE32, and
 * LAVVideo read the Windows 98 process database at fs:[18h]->[+30h] -> page fault in LAVVIDEO.AX). */
void kex_ent_ensure(void) { if (g_ent_state == 0) ent_prepare(); }

/* loader_ext: before loading `name`, switch on what this process needs to load it the NT way:
 * the big-file section hook if it has file data past 256 MB, the DLL-entry hook if it has static TLS. */
void kex_bigsec_prepare(LPCSTR name)
{
    if (g_ent_state == 0 && g_res_n > 0) ent_prepare();      /* the TLS reserve needs the DLL-entry hook */
    char path[MAX_PATH], *fp; HANDLE f; BYTE hdr[0x400]; DWORD rd = 0, fsize; IMAGE_NT_HEADERS32 *nt;
    IMAGE_SECTION_HEADER *sh; int i; BOOL big = FALSE, tls;
    if ((g_big_state != 0 && g_ent_state != 0) || !name) return;
    g_big_prep = 1;
    if (!SearchPathA(NULL, name, ".dll", MAX_PATH, path, &fp)) return;
    g_big_prep = 2;
    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    g_big_prep = 3;
    fsize = GetFileSize(f, NULL);
    ReadFile(f, hdr, sizeof(hdr), &rd, NULL);
    CloseHandle(f);
    if (rd < 0x100 || *(WORD *)hdr != IMAGE_DOS_SIGNATURE || *(DWORD *)(hdr + 0x3C) > 0x300) return;
    nt = (IMAGE_NT_HEADERS32 *)(hdr + *(DWORD *)(hdr + 0x3C));
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return;
    g_big_prep = 4;
    tls = nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS &&
          nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0;
    if (tls && (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) ent_prepare();
    if (g_big_state != 0 || fsize <= BIG_LIMIT) return;
    g_big_prep = 5;
    sh = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections && (BYTE *)(sh + i + 1) <= hdr + sizeof(hdr); i++)
        if (sh[i].SizeOfRawData && sh[i].PointerToRawData + sh[i].SizeOfRawData > BIG_LIMIT) big = TRUE;
    if (!big) return;
    g_big_prep = 6;
    {
        LONG st = big_activate();
        InterlockedCompareExchange(&g_big_state, st, 0);
        if (st < 0) OutputDebugStringA("KernelEx-NG: big-file section hook unavailable (see KexBigSecState)\n");
    }
}

/* Diagnostics: state (1 live, 0 not needed yet, <0 reason, -20 disabled by KEXNG_NOBIGSEC), calls, failures */
LONG KEXAPI kex_KexBigSecState(PDWORD calls, PDWORD fails)
{
    if (calls) *calls = (DWORD)g_big_calls;
    if (fails) *fails = (DWORD)g_big_fail | ((DWORD)g_big_prep << 24);   /* top byte: prepare progress 0-6 */
    return g_big_state;
}

/* Diagnostics/tests: activate the hook in this process now (as loading a big DLL would). Returns the state. */
LONG KEXAPI kex_KexBigSecActivate(void)
{
    if (g_big_state == 0) { LONG st = big_activate(); InterlockedCompareExchange(&g_big_state, st, 0); }
    return g_big_state;
}

LONG KEXAPI kex_KexTlsEntryActivate(void) { ent_prepare(); return g_ent_state; }

/* ================================================================ DLLs without relocations (2026-11-21, build 132)
 * NT moves a DLL whose preferred base is taken unless its header says IMAGE_FILE_RELOCS_STRIPPED; with an empty
 * relocation directory there is simply nothing to fix up. Windows 98 SE KERNEL32 (4.10.2222: 0xBFF87A7A), after
 * _PageReserve at the preferred base failed, moves the image only if the relocation directory is larger than 4
 * bytes, else fails the load with ERROR_BAD_FORMAT:
 *     83 BE A4 00 00 00 04   cmp dword [esi+0A4h],4      ; NT headers copy: DataDirectory[BASERELOC].Size
 *     77 0C                  ja  relocate
 *     6A 0B FF 75 08 6A 0C   push 0Bh / ... -> error 11
 * Microsoft's app-local api-ms-win-*.dll (Mypal, Firefox 52+, Pale Moon) all ask for 0x10000000, have
 * Characteristics 0x2102 (relocations NOT stripped) and a 0/0 relocation directory (no code, only exports), so
 * only the first one loaded. Measured with probes/rlc.c: second DLL -> err 11; the same file with a directory
 * size of 8 -> loaded at 00C80000 (the relocate path; KERNEL32's per-page fixer returns early when the module
 * has no relocation index, 0xBFF98C85).
 * Patch: the 9 bytes jump to a stub in KERNEL32's .text cave (shared, permanent until reboot):
 *     cmp dword [esi+0A4h],4 / ja relocate                  ; unchanged Windows 98 behaviour
 *     test byte [esi+16h],1 / jnz fail                      ; RELOCS_STRIPPED: refuse, as NT does
 *     cmp word [esi+48h],5 / jae relocate                   ; image built for NT 5+ (MajorSubsystemVersion)
 *     fail: jmp site+9          relocate: jmp site+15h
 * Images built for Windows 9x (subsystem 4.x) keep Windows 98's rule, so native programs are not affected.
 * Installed by modern programs' kexnt start-up and at boot (RunServices "KexNGLoader": rundll32 kexnt,KexNGBoot)
 * so it is in place before the first modern program maps its own DLLs. Nothing of KERNEL32 is copied. */
#define RLC_MAGIC 0x3152584BUL      /* "KXR1" */
typedef struct { DWORD magic; BYTE saved[12]; BYTE code[48]; } rlc_stub;
static const BYTE g_rlc_pat[] = { 0x83, 0xBE, 0xA4, 0x00, 0x00, 0x00, 0x04, 0x77, 0x0C, 0x6A, 0x0B, 0xFF, 0x75, 0x08, 0x6A, 0x0C };
static LONG g_rlc_state;            /* 0 not tried, 1 live (ours or found installed), <0 reason */

static BYTE *find_rlc(BOOL *hooked)
{
    BYTE *b = (BYTE *)k32(), *found = NULL;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    int s;
    for (s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++) {
        BYTE *p, *end;
        if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE) || !memcmp(sec->Name, "_INIT", 6)) continue;
        p = b + sec->VirtualAddress; end = p + sec->Misc.VirtualSize;
        if (IsBadReadPtr(p, sec->Misc.VirtualSize)) continue;
        for (; p + sizeof(g_rlc_pat) <= end; p++) {
            BOOL h = p[0] == 0xE9 && p[5] == 0x90 && p[6] == 0x90 && p[7] == 0x90;
            if (memcmp(p + 9, g_rlc_pat + 9, sizeof(g_rlc_pat) - 9)) continue;
            if (!h && memcmp(p, g_rlc_pat, 9)) continue;
            if (h) {        /* ours? the jump must land on a stub with our magic */
                rlc_stub *st = (rlc_stub *)((p + 5 + *(LONG *)(p + 1)) - offsetof(rlc_stub, code));
                if (IsBadReadPtr(st, sizeof(*st)) || st->magic != RLC_MAGIC) continue;
            }
            if (found && found != p) return NULL;
            found = p; *hooked = h;
        }
    }
    return found;
}

static LONG rlc_install(void)
{
    BYTE *site, *c; BOOL hooked = FALSE; rlc_stub *stub; HANDLE mtx; LONG why = 1; DWORD le = GetLastError();
    BYTE *j_reloc1, *j_fail, *j_reloc2;
    if (!kex_is_win9x()) return -1;
    mtx = CreateMutexA(NULL, FALSE, "KexNgVehInstall");
    if (mtx) WaitForSingleObject(mtx, INFINITE);
    if (!(site = find_rlc(&hooked))) { why = -3; goto out; }
    if (hooked) goto out;
    if (!(stub = (rlc_stub *)k32_cave((sizeof(rlc_stub) + 15) & ~15UL))) { why = -5; goto out; }
    k32_writable(stub, sizeof(*stub), TRUE);
    if (IsBadWritePtr(stub, sizeof(*stub))) { why = -11; goto out; }
    stub->magic = RLC_MAGIC; memcpy(stub->saved, site, 12);
    c = stub->code;
    *c++ = 0x83; *c++ = 0xBE; *(DWORD *)c = 0xA4; c += 4; *c++ = 0x04;            /* cmp dword [esi+0A4h],4 */
    *c++ = 0x0F; *c++ = 0x87; j_reloc1 = c; c += 4;                               /* ja relocate */
    *c++ = 0xF6; *c++ = 0x46; *c++ = 0x16; *c++ = 0x01;                           /* test byte [esi+16h],1 */
    *c++ = 0x0F; *c++ = 0x85; j_fail = c; c += 4;                                 /* jnz fail */
    *c++ = 0x66; *c++ = 0x83; *c++ = 0x7E; *c++ = 0x48; *c++ = 0x05;              /* cmp word [esi+48h],5 */
    *c++ = 0x0F; *c++ = 0x83; j_reloc2 = c; c += 4;                               /* jae relocate */
    *(LONG *)j_fail = (LONG)(c - (j_fail + 4));
    *c++ = 0xE9; *(LONG *)c = (LONG)((site + 9) - (c + 4)); c += 4;               /* fail: jmp site+9 */
    *(LONG *)j_reloc1 = (LONG)(c - (j_reloc1 + 4));
    *(LONG *)j_reloc2 = (LONG)(c - (j_reloc2 + 4));
    *c++ = 0xE9; *(LONG *)c = (LONG)((site + 0x15) - (c + 4)); c += 4;            /* relocate: jmp site+15h */
    k32_writable(stub, sizeof(*stub), FALSE);
    {   ULONGLONG oldv, newv; BYTE nb[8];
        nb[0] = 0xE9; *(LONG *)(nb + 1) = (LONG)(stub->code - (site + 5)); nb[5] = nb[6] = nb[7] = 0x90;
        memcpy(&oldv, site, 8); memcpy(&newv, nb, 8);
        k32_writable(site, 8, TRUE);
        if (IsBadWritePtr(site, 8)) { why = -11; goto out; }
        if (!__sync_bool_compare_and_swap((volatile ULONGLONG *)site, oldv, newv)) why = -7;
        k32_writable(site, 8, FALSE);
    }
out:
    if (mtx) { ReleaseMutex(mtx); CloseHandle(mtx); }
    SetLastError(le);
    return why;
}

/* ================================================================ forwarders of NT 5+ DLLs (2026-11-21, build 132)
 * Mypal's own api-ms-win-core-*.dll forward to kernel32/ntdll/advapi32 ("HeapQueryInformation=kernel32.
 * HeapQueryInformation"). Measured (KEXCRASH_LDL5.LOG): "The UCRTBASE.DLL file is linked to missing export
 * API-MS-WIN-CORE-HEAP-L1-1-0.DLL:HeapQueryInformation"; a test DLL importing InitializeCriticalSectionEx through
 * Mypal's api-ms-win-core-synch-l1-1-0.dll: the same. On NT a forwarder gives exactly what a direct kernel32 import
 * gives. With KernelEx, a module outside SYSTEM has no API table (core/resolver.cpp resolve_mod_index), so its
 * exports go through KernelEx's own OriExportFromOrdinal, whose forwarder branch is
 *     GetModuleHandle(module) / GetProcAddress(module, name)      ("//should be IGetProcAddress")
 * called from KernelEx.dll itself - a shared module, which always gets the plain Windows 98 API (get_config:
 * "shared modules should use standard api"). KernelEx.dll 4.5.2 at 0xBFA05240:
 *     56 / 50 / FF 15 <IAT GetProcAddress>        push esi (name) / push eax (module) / call
 *   with the forwarding DLL's NT headers at [esp+110h] (function prologue: sub esp,104h / push esi / push edi).
 * Patch: those 8 bytes jump to a stub in a page of the shared arena that belongs to no module:
 *     mov ecx,[esp+110h] / cmp word [ecx+48h],5 / jb orig   ; forwarding DLL built for NT 5+ (MajorSubsystemVersion)?
 *     push esi / push eax / call [GetProcAddress] / jmp back  ; KERNEL32's GetProcAddress jumps into the lookup KernelEx
 *                                                           ; hooks; the caller address is in no module -> KernelEx's
 *                                                           ; documented fallback: the process's EXE configuration
 *   orig: push esi / push eax / push back / jmp [GetProcAddress]   ; exactly the original call
 * So a program's own forwarder DLLs resolve the way its own kernel32 imports do, and DLLs built for Windows 9x keep
 * KernelEx's behaviour bit for bit. Page: VMM _PageReserve(PR_SHARED, PR_STATIC) + _PageCommit (documented
 * services, as KERNEL32 itself calls them), never freed; found again through the patched jump. */
#define FWD_MAGIC 0x3146584BUL      /* "KXF1" */
static const BYTE g_fwd_pat[] = { 0x85, 0xC0, 0x74, 0x20 };

static BYTE *find_fwd(BOOL *hooked)
{
    BYTE *b, *found = NULL;
    IMAGE_NT_HEADERS *nt; IMAGE_SECTION_HEADER *sec; int s;
    b = kex_core();             /* also when KernelEx.dll is not in this process's module list (boot rundll32) */
    if (!b || IsBadReadPtr(b, 0x400)) return NULL;
    nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew); sec = IMAGE_FIRST_SECTION(nt);
    for (s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++) {
        BYTE *p, *end;
        if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE)) continue;
        p = b + sec->VirtualAddress; end = p + sec->Misc.VirtualSize;
        if (IsBadReadPtr(p, sec->Misc.VirtualSize)) continue;
        for (; p + 24 <= end; p++) {
            BYTE *h = p + 4; BOOL hk;
            if (memcmp(p, g_fwd_pat, sizeof(g_fwd_pat)) || h[8] != 0x5F || h[9] != 0x5E || h[10] != 0x81 || h[11] != 0xC4 ||
                *(DWORD *)(h + 12) != 0x104 || h[16] != 0xC2 || h[17] != 0x08) continue;
            hk = h[0] == 0xE9 && h[5] == 0x90 && h[6] == 0x90 && h[7] == 0x90;
            if (!hk && !(h[0] == 0x56 && h[1] == 0x50 && h[2] == 0xFF && h[3] == 0x15)) continue;
            if (hk) {
                DWORD *pg = (DWORD *)(((ULONG_PTR)(h + 5 + *(LONG *)(h + 1))) & ~0xFFFUL);
                if (IsBadReadPtr(pg, 16) || pg[0] != FWD_MAGIC) continue;
            }
            if (found && found != h) return NULL;
            found = h; *hooked = hk;
        }
    }
    return found;
}

typedef DWORD (WINAPI *VXDCALL3)(DWORD svc, DWORD a, DWORD b, DWORD c);
typedef DWORD (WINAPI *VXDCALL5)(DWORD svc, DWORD a, DWORD b, DWORD c, DWORD d, DWORD e);

/* Part 2 (fwdload_pic.c has the measurements): forwarders whose target DLL is not loaded yet are resolved to thunks
 * that load the target on first call. Page layout: 0 header {magic, GetProcAddress IAT, back}, 16 GetProcAddress
 * stub, 96 GetModuleHandleA glue, 128 context, 256 resolver glue, 320 copy of the kxpic_* functions.
 *   GetProcAddress stub (KernelEx.dll 0xBFA05240, NT 5+ forwarding DLL): push esi / push eax / push ctx /
 *       call kxpic_fwd_gpa / jmp back
 *   GetModuleHandleA glue (KernelEx.dll 0xBFA05236: FF 15 <IAT> -> E8 <glue> 90):
 *       push [esp+118h] (forwarding DLL's NT headers) / push [esp+8] (name) / push ctx / call kxpic_fwd_gmh / ret 4
 *   resolver glue (a thunk did "push thunk / jmp glue"):
 *       pushad / push [esp+20h] / push ctx / call kxpic_fwd_resolve / mov [esp+20h],eax / popad / ret
 *     -> returns into the function with the caller's stack and registers untouched. */
typedef struct fwd_ctx {
    DWORD magic, gmh_iat, gpa_iat; void *valloc, *loadlib, *psget, *psset; int ps_slot; BYTE *resolver;
    volatile LONG markers, thunks, resolved, unresolved, loads;
} fwd_ctx;
HMODULE WINAPI kxpic_fwd_gmh(fwd_ctx *c, LPCSTR name, const IMAGE_NT_HEADERS32 *fwd);   /* fwdload_pic.c */
FARPROC WINAPI kxpic_fwd_gpa(fwd_ctx *c, HMODULE h, LPCSTR name);
FARPROC WINAPI kxpic_fwd_resolve(fwd_ctx *c, void *thunk);
void kxpic_fwd_end(void);
static fwd_ctx *g_fwd_ctx;
void kxpic_section_start(void);                                                      /* fwdload_pic.c, first */

static LONG fwd_install(void)
{
    BYTE *h, *site2, *back, *c, *j_orig, *page, *pic, *start; DWORD iat, len; BOOL hooked = FALSE; DWORD addr; HANDLE mtx;
    LONG why = 1; DWORD le = GetLastError(); fwd_ctx *x;
    VXDCALL3 vxd3 = (VXDCALL3)k32_ordinal(4); VXDCALL5 vxd5 = (VXDCALL5)k32_ordinal(6);
    if (!kex_is_win9x()) return -1;
    if (!vxd3 || !vxd5) return -2;
    start = (BYTE *)kxpic_section_start; len = (DWORD)((BYTE *)kxpic_fwd_end - start);
    if (len < 64 || len > 4096 - 320) return -22;
    mtx = CreateMutexA(NULL, FALSE, "KexNgVehInstall");
    if (mtx) WaitForSingleObject(mtx, INFINITE);
    if (!(h = find_fwd(&hooked))) { why = -3; goto out; }
    if (hooked) {
        page = (BYTE *)(((ULONG_PTR)(h + 5 + *(LONG *)(h + 1))) & ~0xFFFUL);
        if (((fwd_ctx *)(page + 128))->magic == FWD_MAGIC) g_fwd_ctx = (fwd_ctx *)(page + 128);
        goto out;
    }
    site2 = h - 10;
    if (site2[0] != 0xFF || site2[1] != 0x15 || site2[6] != 0x85 || site2[7] != 0xC0) { why = -21; goto out; }
    if (ps_init() != 1) { why = -23; goto out; }
    iat = *(DWORD *)(h + 4); back = h + 8;
    addr = vxd3(0x00010000, 0x80060000, 1, 0x10);                     /* _PageReserve(PR_SHARED, 1, PR_STATIC) */
    if (addr == 0xFFFFFFFF || addr < 0x80000000UL) { why = -4; goto out; }
    if (!vxd5(0x00010001, addr >> 12, 1, 1, 0, 0x20060000)) { why = -5; goto out; }   /* _PageCommit(ZEROINIT, STATIC|USER|WRITEABLE) */
    page = (BYTE *)(ULONG_PTR)addr;
    if (IsBadWritePtr(page, 4096)) { why = -11; goto out; }
    pic = page + 320;
    memcpy(pic, start, len);
#define PIC_FN(f) (pic + ((BYTE *)(f) - start))
    x = (fwd_ctx *)(page + 128);
    x->gmh_iat = *(DWORD *)(site2 + 2); x->gpa_iat = iat;
    x->valloc = k32_export("VirtualAlloc"); x->loadlib = k32_export("LoadLibraryA");
    x->psget = (void *)p_psget; x->psset = (void *)p_psset; x->ps_slot = p_psalloc();
    x->resolver = page + 256;
    if (!x->valloc || !x->loadlib || x->ps_slot <= 0) { why = -24; goto out; }
    x->magic = FWD_MAGIC;
    ((DWORD *)page)[0] = FWD_MAGIC; ((DWORD *)page)[1] = iat; ((DWORD *)page)[2] = (DWORD)(ULONG_PTR)back;
    c = page + 256;                                                       /* resolver glue */
    *c++ = 0x60;                                                          /* pushad */
    *c++ = 0xFF; *c++ = 0x74; *c++ = 0x24; *c++ = 0x20;                  /* push [esp+20h] (thunk) */
    *c++ = 0x68; *(DWORD *)c = (DWORD)(ULONG_PTR)x; c += 4;               /* push ctx */
    *c++ = 0xE8; *(LONG *)c = (LONG)(PIC_FN(kxpic_fwd_resolve) - (c + 4)); c += 4;
    *c++ = 0x89; *c++ = 0x44; *c++ = 0x24; *c++ = 0x20;                  /* mov [esp+20h],eax */
    *c++ = 0x61; *c++ = 0xC3;                                             /* popad / ret */
    c = page + 96;                                                        /* GetModuleHandleA glue */
    {   BYTE *glue = c;
        *c++ = 0xFF; *c++ = 0xB4; *c++ = 0x24; *(DWORD *)c = 0x118; c += 4;  /* push [esp+118h] */
        *c++ = 0xFF; *c++ = 0x74; *c++ = 0x24; *c++ = 0x08;                  /* push [esp+8] */
        *c++ = 0x68; *(DWORD *)c = (DWORD)(ULONG_PTR)x; c += 4;               /* push ctx */
        *c++ = 0xE8; *(LONG *)c = (LONG)(PIC_FN(kxpic_fwd_gmh) - (c + 4)); c += 4;
        *c++ = 0xC2; *c++ = 0x04; *c++ = 0x00;                                /* ret 4 */
        c = page + 16;                                                        /* GetProcAddress stub */
        {   BYTE *code = c;
            *c++ = 0x8B; *c++ = 0x8C; *c++ = 0x24; *(DWORD *)c = 0x110; c += 4;  /* mov ecx,[esp+110h] */
            *c++ = 0x66; *c++ = 0x83; *c++ = 0x79; *c++ = 0x48; *c++ = 0x05;      /* cmp word [ecx+48h],5 */
            *c++ = 0x72; j_orig = c++;                                            /* jb orig */
            *c++ = 0x56; *c++ = 0x50;                                             /* push esi / push eax */
            *c++ = 0x68; *(DWORD *)c = (DWORD)(ULONG_PTR)x; c += 4;               /* push ctx */
            *c++ = 0xE8; *(LONG *)c = (LONG)(PIC_FN(kxpic_fwd_gpa) - (c + 4)); c += 4;
            *c++ = 0xE9; *(LONG *)c = (LONG)(back - (c + 4)); c += 4;             /* jmp back */
            *j_orig = (BYTE)(c - (j_orig + 1));
            *c++ = 0x56; *c++ = 0x50;                                             /* orig: push esi / push eax */
            *c++ = 0x68; *(DWORD *)c = (DWORD)(ULONG_PTR)back; c += 4;            /* push back */
            *c++ = 0xFF; *c++ = 0x25; *(DWORD *)c = iat; c += 4;                  /* jmp [GetProcAddress] */
            if (c > page + 96) { why = -25; goto out; }
            /* GetModuleHandleA site first (harmless alone: it only adds markers our GetProcAddress stub understands -
             * and that stub is installed right after, under the same mutex, before any marker can reach KernelEx) */
            {   ULONGLONG oldv, newv; BYTE nb[8];
                memcpy(nb, h, 8);
                nb[0] = 0xE9; *(LONG *)(nb + 1) = (LONG)(code - (h + 5)); nb[5] = nb[6] = nb[7] = 0x90;
                memcpy(&oldv, h, 8); memcpy(&newv, nb, 8);
                k32_writable(h, 8, TRUE);
                if (IsBadWritePtr(h, 8)) { why = -11; goto out; }
                if (!__sync_bool_compare_and_swap((volatile ULONGLONG *)h, oldv, newv)) { k32_writable(h, 8, FALSE); why = -7; goto out; }
                memcpy(nb, site2, 8);
                nb[0] = 0xE8; *(LONG *)(nb + 1) = (LONG)(glue - (site2 + 5)); nb[5] = 0x90;
                memcpy(&oldv, site2, 8); memcpy(&newv, nb, 8);
                if (!__sync_bool_compare_and_swap((volatile ULONGLONG *)site2, oldv, newv)) why = -27;
                k32_writable(h, 8, FALSE);
            }
        }
    }
    g_fwd_ctx = x;
out:
    if (mtx) { ReleaseMutex(mtx); CloseHandle(mtx); }
    SetLastError(le);
    return why;
}

/* Diagnostics: forwarder markers, thunks, resolved and unresolved thunk calls, target loads (all processes) */
LONG KEXAPI kex_KexFwdStats(PDWORD out5)
{
    if (!g_fwd_ctx) { BOOL hk = FALSE; BYTE *h = find_fwd(&hk);
        if (h && hk) { BYTE *page = (BYTE *)(((ULONG_PTR)(h + 5 + *(LONG *)(h + 1))) & ~0xFFFUL);
            if (((fwd_ctx *)(page + 128))->magic == FWD_MAGIC) g_fwd_ctx = (fwd_ctx *)(page + 128); } }
    if (!g_fwd_ctx) return -1;
    if (out5) { out5[0] = g_fwd_ctx->markers; out5[1] = g_fwd_ctx->thunks; out5[2] = g_fwd_ctx->resolved;
                out5[3] = g_fwd_ctx->unresolved; out5[4] = g_fwd_ctx->loads; }
    return 1;
}
static LONG g_fwd_state;

/* Idempotent; 1 = both live. <0: relocation patch reason (-3 site not found, -5 no cave space, -7/-11 write);
 * <= -100: forwarder patch reason - 100 (-103 site, -104 reserve, -105 commit, -107/-111 write) */
/* HKLM\Software\KernelEx\KexNG "LoaderFix" = DWORD 0 keeps all three loader patches out (A/B tests; reboot after setting) */
static BOOL loaderfix_disabled(void)
{
    HKEY k; DWORD v = 1, t, n = sizeof(v);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, "LoaderFix", NULL, &t, (BYTE *)&v, &n) != ERROR_SUCCESS || t != REG_DWORD) v = 1;
        RegCloseKey(k);
    }
    return v == 0;
}
LONG KEXAPI kex_KexLoaderFix(void)
{
    if (loaderfix_disabled()) return -50;
    if (g_rlc_state <= 0) InterlockedExchange(&g_rlc_state, rlc_install());
    if (g_fwd_state <= 0) InterlockedExchange(&g_fwd_state, fwd_install());
    return g_rlc_state == 1 && g_fwd_state == 1 ? 1 : (g_rlc_state != 1 ? g_rlc_state : g_fwd_state - 100);
}
void kex_loaderfix_ensure(void) { if (g_rlc_state == 0 || g_fwd_state == 0) kex_KexLoaderFix(); }

/* rundll32 entry for the boot-time RunServices value written by KEXSETUP */
void WINAPI kex_KexNGBoot(HWND w, HINSTANCE i, LPSTR cmd, int show) { (void)w; (void)i; (void)cmd; (void)show; kex_KexLoaderFix(); }

void kex_bigsec_detach(void)
{
    if (g_big_state == 1 && p_psset && g_big_ps > 0) p_psset(g_big_ps, NULL);
    if (g_ent_state == 1 && p_psset && g_ent_ps > 0) p_psset(g_ent_ps, NULL);
    { extern LONG g_vxd_ps_pub; if (g_vxd_ps_pub > 0 && p_psset) p_psset(g_vxd_ps_pub, NULL); g_vxd_ps_pub = -1; }
    g_big_state = 0; g_ent_state = 0;
}

/* ================================================================ VirtualProtect on big-file sections
 * 2026-11-01 15:50: blue screen right after Chrome's VirtualProtect(chrome.dll .fptable 0x20AD4000, READWRITE).
 * Windows 98's VirtualProtect (0xBFF99EB4) passes the request to VWIN32 service 0x2A003F, which treats module
 * pages specially; for a section whose file data lies past 256 MB that path meets the same 16-bit file page
 * number as the loader. Pages kex_bigsec_entry committed are ordinary demand-zero memory, so for exactly those
 * ranges kexnt changes the page bits itself with VMM _PageModifyPermissions (as k32_writable does) and never
 * calls Windows' VirtualProtect. */
#define BIG_RANGES 64
static struct { DWORD lo, hi, prot, sec; } g_big_rng[BIG_RANGES];   /* prot: what VirtualQuery reports (0: Windows' value); sec: a section we mapped (not the whole-image entry) */
static volatile LONG g_big_nrng;

/* The pages are committed writable (demand-zero memory the bytes are copied into), whatever the section header
 * says. Windows would map a section without IMAGE_SCN_MEM_WRITE read-only, and programs check that: Chromium's
 * base::ProtectedMemory keeps its data in such a section ("prot", chrome.dll 0x20AD8000) and CHECKs that
 * VirtualQuery reports PAGE_READONLY (protected_memory_win.cc:43, 2026-11-02). The page bits stay writable
 * (the loader may still apply relocations); VirtualQuery reports the section's protection instead, and
 * VirtualProtect on these ranges (kex_bigsec_protect) updates what is reported. */
static void big_remember(BYTE *addr, DWORD size, DWORD characteristics)
{
    LONG i = InterlockedIncrement(&g_big_nrng) - 1;
    if (i >= BIG_RANGES) return;
    g_big_rng[i].lo = (DWORD)(ULONG_PTR)addr & ~0xFFFUL;
    g_big_rng[i].hi = ((DWORD)(ULONG_PTR)addr + size + 0xFFF) & ~0xFFFUL;
    g_big_rng[i].sec = characteristics != 0xFFFFFFFFUL;                                 /* ~0: whole image (DLL entry) */
    if (!g_big_rng[i].sec || (characteristics & 0x80000000UL)) g_big_rng[i].prot = 0;  /* MEM_WRITE: as committed */
    else g_big_rng[i].prot = (characteristics & 0x20000000UL) ? PAGE_EXECUTE_READ : PAGE_READONLY;
}

/* For kex_VirtualQuery: the protection to report for a page inside a big-file section range, else 0. */
DWORD kex_bigsec_reported_protect(LPCVOID a)
{
    DWORD p = (DWORD)(ULONG_PTR)a; LONG i, c = g_big_nrng;
    if (c > BIG_RANGES) c = BIG_RANGES;
    for (i = 0; i < c; i++) if (g_big_rng[i].sec && p >= g_big_rng[i].lo && p < g_big_rng[i].hi) return g_big_rng[i].prot;
    return 0;
}

BOOL kex_bigsec_owns(LPCVOID a, SIZE_T n)
{
    DWORD lo = (DWORD)(ULONG_PTR)a, hi = lo + (DWORD)(n ? n : 1); LONG i, c = g_big_nrng;
    if (c > BIG_RANGES) c = BIG_RANGES;
    for (i = 0; i < c; i++) if (lo < g_big_rng[i].hi && hi > g_big_rng[i].lo) return TRUE;
    return FALSE;
}

/* build 77: writes into the SHARED .rdata (every process sees them - Windows 98 has no copy-on-write). Chromium
 * patches import-table entries (sandbox_win.cc:902 DuplicateHandle in the browser) as
 *     VirtualProtect(entry, 4, READWRITE) / write / VirtualProtect(entry, 4, old)
 * The bytes are saved when the range is made writable and put back when it is made read-only again, so the other
 * processes keep calling the real function (the patched one used state they do not have: build 10, address 0).
 * The program loses that hook - a check of its own sandbox, which is off (--no-sandbox). Each undo goes to KEXCRASH. */
#define RP_MAX 32
static struct { DWORD a, n; BYTE b[64]; } g_rp[RP_MAX];
static volatile LONG g_rp_lock, g_rp_notes;
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */
static void rdata_patch(DWORD a, DWORD n, BOOL writable)
{
    int i;
    if (!g_rd_lo || !n || a >= g_rd_hi || a + n <= g_rd_lo) return;
    kex_spin_acquire(&g_rp_lock);
    /* build 78: a second protection change on a saved range IS the restore, whatever protection it asks for */
    if (writable) for (i = 0; i < RP_MAX; i++) if (g_rp[i].n && g_rp[i].a == a && g_rp[i].n == n) { writable = FALSE; break; }
    if (writable) {
        if (n <= 64 && !IsBadReadPtr((void *)(ULONG_PTR)a, n)) {
            for (i = 0; i < RP_MAX && g_rp[i].n && g_rp[i].a != a; i++) ;
            if (i < RP_MAX && !g_rp[i].n) { g_rp[i].a = a; g_rp[i].n = n; memcpy(g_rp[i].b, (void *)(ULONG_PTR)a, n); }
        } else if (InterlockedIncrement(&g_rp_notes) <= 20)
            kex_crashnote("shared .rdata: large range made writable - writes into it reach every process (address, size)", a, n, 0, 0);
    } else {
        for (i = 0; i < RP_MAX; i++) {
            if (!g_rp[i].n || g_rp[i].a + g_rp[i].n <= a || g_rp[i].a >= a + n) continue;
            if (memcmp((void *)(ULONG_PTR)g_rp[i].a, g_rp[i].b, g_rp[i].n)) {
                DWORD was = *(DWORD *)(ULONG_PTR)g_rp[i].a;
                memcpy((void *)(ULONG_PTR)g_rp[i].a, g_rp[i].b, g_rp[i].n);
                if (InterlockedIncrement(&g_rp_notes) <= 20)
                    kex_crashnote("shared .rdata: import-table patch undone, the other processes keep the real function (address, size, patched value, original)",
                                  g_rp[i].a, g_rp[i].n, was, *(DWORD *)g_rp[i].b);
            }
            g_rp[i].n = 0;
        }
    }
    InterlockedExchange(&g_rp_lock, 0);
}

#define PC_WRITEABLE 0x00020000UL
#define PC_USER      0x00040000UL
BOOL kex_bigsec_protect(LPVOID a, SIZE_T n, DWORD prot, PDWORD old)
{
    VXDCALL4 vxd4 = (VXDCALL4)k32_ordinal(5);
    MEMORY_BASIC_INFORMATION m;
    DWORD first = (DWORD)(ULONG_PTR)a >> 12, last = ((DWORD)(ULONG_PTR)a + (DWORD)(n ? n : 1) - 1) >> 12;
    DWORD pand, por, p = prot & 0xFF;
    if (!vxd4) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    /* build 78: the OLD protection is what VirtualQuery REPORTS (the section's), not the page bits (committed
     * writable): Chromium's ModifyCode restores with this value, and build 77 handed back PAGE_READWRITE, so the
     * restore looked like another "make writable" and the import-table patch was never undone. */
    if (old) { DWORD rp = kex_bigsec_reported_protect(a); *old = rp ? rp : VirtualQuery(a, &m, sizeof(m)) ? m.Protect : PAGE_READWRITE; }
    rdata_patch((DWORD)(ULONG_PTR)a, (DWORD)n, p == PAGE_READWRITE || p == PAGE_EXECUTE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY);
    if (p == PAGE_NOACCESS) { pand = ~(PC_WRITEABLE | PC_USER); por = 0; }
    else if (p == PAGE_READWRITE || p == PAGE_EXECUTE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY)
         { pand = 0xFFFFFFFFUL; por = PC_WRITEABLE | PC_USER; }
    else { pand = ~PC_WRITEABLE; por = PC_USER; }                   /* READONLY / EXECUTE / EXECUTE_READ */
    vxd4(0x0001000D, first, last - first + 1, pand, por);              /* VMM _PageModifyPermissions */
    {   LONG i, c = g_big_nrng; DWORD lo = first << 12, hi = (last + 1) << 12;
        if (c > BIG_RANGES) c = BIG_RANGES;
        for (i = 0; i < c; i++) if (g_big_rng[i].sec && lo < g_big_rng[i].hi && hi > g_big_rng[i].lo) g_big_rng[i].prot = p; }
    kex_trace("  bigsec protect", first, last - first + 1, pand, por);
    return TRUE;
}

/* The text Windows 98 composes when a load fails on a missing import ("X is linked to missing export Y:Z") -
 * kept in a KERNEL32 global that only the Explorer error box shows. Found by its store: 83 C4 04 A3 <ptr> 6A 1F E8. */
static DWORD *g_loadmsg_slot; static BOOL g_loadmsg_tried;
static void loadmsg_find(void);
const char *kex_k32_load_message(void)
{
    DWORD *slot;
    loadmsg_find();
    slot = g_loadmsg_slot;
    if (!slot || IsBadReadPtr(slot, 4) || !*slot || IsBadStringPtrA((const char *)(ULONG_PTR)*slot, 512)) return NULL;
    return (const char *)(ULONG_PTR)*slot;
}
/* before a load: forget the previous message, so a message after a failure belongs to this load (the old string
 * stays allocated in KERNEL32's heap - a few hundred bytes per earlier failure) */
void kex_k32_clear_load_message(void)
{
    loadmsg_find();
    if (g_loadmsg_slot && !IsBadWritePtr(g_loadmsg_slot, 4)) *g_loadmsg_slot = 0;
}
static void loadmsg_find(void)
{
    DWORD **pslot = &g_loadmsg_slot;
    if (!g_loadmsg_tried) {
        BYTE *b = (BYTE *)k32(); IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
        IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt); int s; BYTE *found = NULL;
        g_loadmsg_tried = TRUE;
        for (s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++) {
            BYTE *p, *end;
            if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE) || !memcmp(sec->Name, "_INIT", 6)) continue;
            p = b + sec->VirtualAddress; end = p + sec->Misc.VirtualSize;
            if (IsBadReadPtr(p, sec->Misc.VirtualSize)) continue;
            for (; p + 11 <= end; p++)
                if (p[0] == 0x83 && p[1] == 0xC4 && p[2] == 0x04 && p[3] == 0xA3 && p[8] == 0x6A && p[9] == 0x1F && p[10] == 0xE8) {
                    if (found) return;               /* ambiguous */
                    found = p;
                }
        }
        if (found) *pslot = *(DWORD **)(found + 4);
    }
}

/* ================================================================ VxDCall trace (diagnostics, 2026-11-01)
 * Chromium blue-screened Windows 98 twice more at "fatal exception 0D at 0028:BFF713DB" = the
 * `call fword ptr cs:[...]` of KERNEL32's VxDCall thunk (0xBFF713D4, KERNEL32 ordinals 1-9: VxDCall0..8):
 *     8B 44 24 04  mov eax,[esp+4]   (service id)
 *     8F 04 24     pop dword [esp]   (return address over the id)
 *     2E FF 1D ..  call fword cs:[gate]
 * Every ring-3 request to the VMM/VxDs from KERNEL32 goes through it. In NT 6+ processes (crash log armed) kexnt
 * hooks it (same machinery, magic KXV1) and writes each distinct (service, caller) pair to KEXTRACE.LOG the first
 * time it is seen - queued BEFORE the call is made, written by a helper thread (see kex_vxd_log). The last such line before a blue
 * screen is the request that killed Windows. KEXNG_NOVXDTRACE=1 switches it off. */
#define VXD_MAGIC 0x3156584BUL       /* "KXV1" */
static void *g_vxd_orig __attribute__((used));
static LONG  g_vxd_state;
static LONG  g_vxd_ps = -1;
LONG g_vxd_ps_pub = -1;              /* read by kex_bigsec_detach (defined earlier in this file) */
static DWORD g_vxd_tls = TLS_OUT_OF_INDEXES;   /* only marks "set up"; the per-thread guard is vxd_busy */
/* Per-thread "inside the VxD logger" marks without TLS (2026-11-02): with a KernelEx-extended TLS slot
 * TlsGetValue/TlsSetValue can allocate memory, i.e. call VxDs, i.e. come back here - a thread starting up
 * at process exit recursed until its stack ran out (kextest + DWrite, KERNEL32 fault with ESP on a 64 KB
 * boundary). A small table of thread ids, no allocation. */
#define VXD_BUSY 64
static volatile DWORD g_vxd_busy[VXD_BUSY];
static DWORD vxd_get(void)
{
    DWORD t = GetCurrentThreadId(), i;
    for (i = 0; i < VXD_BUSY; i++) if (g_vxd_busy[i] == t) return 1;
    return 0;
}
static void vxd_set(DWORD on)
{
    DWORD t = GetCurrentThreadId(), i;
    if (on) {
        for (i = 0; i < VXD_BUSY; i++) if (g_vxd_busy[i] == t) return;
        for (i = 0; i < VXD_BUSY; i++) if (InterlockedCompareExchange((LONG *)&g_vxd_busy[i], (LONG)t, 0) == 0) return;
    } else {
        for (i = 0; i < VXD_BUSY; i++) if (g_vxd_busy[i] == t) { g_vxd_busy[i] = 0; return; }
    }
}
static DWORD g_vxd_seen[2048];
static volatile LONG g_vxd_lock;

static int emit_vxd(big_stub *s, BYTE *fn)
{
    BYTE *c = s->code, *j[2]; int n = 0, i, off;
    *c++ = 0xA1; *(DWORD *)c = s->ppdb; c += 4;                         /* mov eax,[ppdbCur] */
    *c++ = 0x8B; *c++ = 0x00;                                           /* mov eax,[eax] */
    *c++ = 0x8B; *c++ = 0x80; *(DWORD *)c = s->pdb_off; c += 4;         /* mov eax,[eax+pdb_off] */
    *c++ = 0x85; *c++ = 0xC0; *c++ = 0x74; j[n++] = c++;                /* test / jz orig */
    *c++ = 0x8B; *c++ = 0x80; *(DWORD *)c = s->slot_off; c += 4;        /* mov eax,[eax+slot_off] */
    *c++ = 0x85; *c++ = 0xC0; *c++ = 0x74; j[n++] = c++;                /* test / jz orig */
    *c++ = 0xFF; *c++ = 0xE0;                                           /* jmp eax */
    for (i = 0; i < n; i++) *j[i] = (BYTE)(c - (j[i] + 1));
    off = (int)(c - s->code);
    *c++ = 0x8B; *c++ = 0x44; *c++ = 0x24; *c++ = 0x04;                 /* mov eax,[esp+4] */
    *c++ = 0x8F; *c++ = 0x04; *c++ = 0x24;                              /* pop dword [esp] */
    *c++ = 0xE9; *(LONG *)c = (LONG)((fn + 7) - (c + 4)); c += 4;       /* jmp thunk+7 (the far call) */
    return off;
}

/* cdecl, from the asm entry: st -> [ret][service][arg0][arg1][arg2]... */
/* No file I/O on the calling thread: KERNEL32 often makes VxD calls while holding its own locks, and writing a
 * file there deadlocked Windows (2026-11-01 16:19 freeze with the first version). The calling thread only puts a
 * new (service, caller) pair into a ring in memory and pauses 15 ms (bounded - it never waits for anyone); a
 * helper thread writes the ring to KEXTRACE.LOG. A blue screen right after a new pair is very likely to find it
 * already on disk. */
#define VXD_RING 512
static struct { DWORD svc, caller, arg0, app, tick, tid; } g_vxd_ring[VXD_RING];
static volatile LONG g_vxd_head, g_vxd_tail;

static volatile LONG g_vxd_calls, g_vxd_new, g_vxd_written, g_vxd_flushers, g_vxd_alive, g_vxd_drainlock;
void kex_trace_raw(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

/* Write out what is queued. Called by the flusher thread and - since 2026-11-01 21:00, when three Chrome processes
 * wrote "vxd trace on" and then not a single sighting - also at the start of every kex_trace line (API wrappers:
 * never inside KERNEL32), so the ring reaches the file even if the flusher thread never runs. */
void kex_vxd_drain(void)
{
    DWORD prev;
    if (g_vxd_state != 1 || g_vxd_tail == g_vxd_head) return;
    if (InterlockedExchange((LONG *)&g_vxd_drainlock, 1)) return;
    prev = vxd_get();
    vxd_set(1);                                            /* our own file I/O is not logged */
    while (g_vxd_tail != g_vxd_head) {
        LONG i = g_vxd_tail % VXD_RING;
        char what[32] = "vxd t=";
        static const char hx[] = "0123456789abcdef"; int k;
        for (k = 0; k < 8; k++) what[6 + k] = hx[(g_vxd_ring[i].tid >> (28 - 4 * k)) & 15];
        what[14] = 0;
        kex_trace_raw(what, g_vxd_ring[i].svc, g_vxd_ring[i].caller, g_vxd_ring[i].arg0, g_vxd_ring[i].app);
        InterlockedIncrement((LONG *)&g_vxd_tail);
        InterlockedIncrement((LONG *)&g_vxd_written);
    }
    vxd_set(prev);
    InterlockedExchange((LONG *)&g_vxd_drainlock, 0);
}

static DWORD WINAPI vxd_flusher(LPVOID p)
{
    (void)p;
    vxd_set(1);                                            /* this thread's own calls are never logged */
    if (InterlockedIncrement((LONG *)&g_vxd_alive) == 1) kex_trace_raw("vxd flusher running", GetCurrentThreadId(), 0, 0, 0);
    for (;;) { kex_vxd_drain(); Sleep(4); }
}

/* for the exit summary in KEXCRASH.LOG */
void kex_vxd_stats(DWORD v[6])
{
    v[0] = (DWORD)g_vxd_state; v[1] = g_vxd_calls; v[2] = g_vxd_new; v[3] = g_vxd_written; v[4] = g_vxd_flushers; v[5] = g_vxd_alive;
}

void __cdecl kex_vxd_log(DWORD *st)
{
    DWORD le = GetLastError(), key, h, i, app = 0, k; BOOL fresh = FALSE;
    InterlockedIncrement((LONG *)&g_vxd_calls);
    if (vxd_get()) { SetLastError(le); return; }
    vxd_set(1);
    key = (st[1] * 0x9E3779B1UL) ^ st[0];
    if (!key) key = 1;
    /* 1. seen before? (lock held only for the table) */
    /* build 131: bounded - the owner may be a terminated or suspended thread (kex_spin_try); then this call is not logged */
    if (!kex_spin_try(&g_vxd_lock, 200)) { vxd_set(0); SetLastError(le); return; }
    for (h = key & 2047, i = 0; i < 2048; i++, h = (h + 1) & 2047) {
        if (g_vxd_seen[h] == key) break;
        if (!g_vxd_seen[h]) { g_vxd_seen[h] = key; fresh = TRUE; break; }
    }
    InterlockedExchange(&g_vxd_lock, 0);
    if (fresh) {
        /* 2. the program's return address on the stack (no lock held: these probes may fault) */
        for (k = 2; k < 96 && !IsBadReadPtr(st + k, 4); k++) {
            DWORD v = st[k];
            if (v < 0x00400000UL || v >= 0x80000000UL || IsBadReadPtr((BYTE *)(ULONG_PTR)v - 6, 6)) continue;
            if (((BYTE *)(ULONG_PTR)v)[-5] == 0xE8 || ((BYTE *)(ULONG_PTR)v)[-6] == 0xFF || ((BYTE *)(ULONG_PTR)v)[-2] == 0xFF ||
                ((BYTE *)(ULONG_PTR)v)[-3] == 0xFF) { app = v; break; }
        }
        /* 3. queue it */
        if (!kex_spin_try(&g_vxd_lock, 200)) { vxd_set(0); SetLastError(le); return; }   /* build 131: bounded */
        if (g_vxd_head - g_vxd_tail < VXD_RING) {
            LONG n = g_vxd_head % VXD_RING;
            g_vxd_ring[n].svc = st[1]; g_vxd_ring[n].caller = st[0]; g_vxd_ring[n].arg0 = st[2]; g_vxd_ring[n].app = app;
            g_vxd_ring[n].tick = 0; g_vxd_ring[n].tid = GetCurrentThreadId();
            InterlockedIncrement(&g_vxd_head);
            InterlockedIncrement((LONG *)&g_vxd_new);
        }
        InterlockedExchange(&g_vxd_lock, 0);
        Sleep(15);                                          /* give the writer a chance before the call runs */
    }
    vxd_set(0);
    SetLastError(le);
}
void kex_vxd_entry(void);
__asm__(
    ".text\n.globl _kex_vxd_entry\n_kex_vxd_entry:\n\t"
    "pushfl\n\t"
    "pushal\n\t"
    "leal 36(%esp), %eax\n\t"        /* 32 (pushal) + 4 (pushfl): -> [ret][service][args] */
    "pushl %eax\n\t"
    "call _kex_vxd_log\n\t"
    "addl $4, %esp\n\t"
    "popal\n\t"
    "popfl\n\t"
    "jmp *_g_vxd_orig\n");

void kex_vxdtrace_activate(void)
{
    BYTE *fn; big_stub *stub; int orig; LONG why; char v[8];
    static const BYTE pat[] = { 0x8B, 0x44, 0x24, 0x04, 0x8F, 0x04, 0x24, 0x2E, 0xFF, 0x1D };
    if (g_vxd_state) return;
    g_vxd_state = -1;
    if (GetEnvironmentVariableA("KEXNG_NOVXDTRACE", v, sizeof(v)) && v[0] == '1') { g_vxd_state = -20; return; }
    fn = (BYTE *)k32_ordinal(1);                                        /* VxDCall0 */
    if (!fn || IsBadReadPtr(fn, 16)) { g_vxd_state = -3; return; }
    if (!(fn[0] == 0xE9 && fn[5] == 0x90 && !memcmp(fn + 7, pat + 7, 3)) && memcmp(fn, pat, sizeof(pat))) { g_vxd_state = -3; return; }
    if ((g_vxd_tls = TlsAlloc()) == TLS_OUT_OF_INDEXES) { g_vxd_state = -6; return; }
    { DWORD tid; HANDLE t = CreateThread(NULL, 0x10000, vxd_flusher, NULL, 0, &tid);
      if (!t) { g_vxd_state = -21; return; }
      InterlockedIncrement((LONG *)&g_vxd_flushers);
      SetThreadPriority(t, THREAD_PRIORITY_ABOVE_NORMAL); CloseHandle(t); }
    if (!g_big_modtab) { BYTE *ms = find_mapsec(); if (ms) g_big_modtab = *(DWORD *)(ms + 14); }
    why = hook_activate(fn, VXD_MAGIC, emit_vxd, (void *)kex_vxd_entry, &stub, &orig);
    if (why != 1) { g_vxd_state = why; return; }
    g_vxd_orig = stub->code + orig;
    g_vxd_ps = stub->ps_index; g_vxd_ps_pub = g_vxd_ps;
    g_vxd_state = 1;
    kex_trace("vxd trace on (service caller arg0 &stack)", (DWORD)(ULONG_PTR)fn, 0, 0, 0);
}

