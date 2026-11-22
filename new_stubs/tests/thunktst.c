/*
 * thunktst.c - THUNKTST.EXE: measures how often Windows 98 USER32/GDI32 calls (32->16 bit thunks) come back with
 * the stack pointer or the callee-saved registers (EBX ESI EDI EBP) wrong. Plain Win32, needs nothing else
 * (no KernelEx). Written for the Explorer / Chrome crashes on VMware + Ryzen that do not happen on 86Box.
 *
 *   THUNKTST [seconds per phase, default 60]
 *
 * Phases (each the same length):
 *   A  1 worker thread calling USER32/GDI32 functions in a loop
 *   B  4 worker threads
 *   C  4 worker threads + a thread that keeps committing / freeing / touching memory (page-table changes)
 *   D  1 worker thread + the memory thread
 * Every call goes through check_call: EBX/ESI/EDI/EBP get known values, ESP is recorded, and after the call all
 * of them are compared. A wrong one is counted and the thread is put back (ESP/EBP/registers from a save area
 * whose address is in TIB+0x14), so the test keeps running. Results: C:\THUNKTST.LOG and on screen.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

typedef struct {
    DWORD esp_before, esp_after, ebx, esi, edi, ebp, ret;     /* written by check_call after the call */
    DWORD save_ebp, save_esp;                                  /* check_call's own frame */
} CSAVE;

/* DWORD check_call(void *fn, int nargs, const DWORD *args, CSAVE *s)  (cdecl)
 * returns 0 if ESP/EBX/ESI/EDI/EBP were fine after the call, else 1 (details in *s) */
DWORD check_call(void *fn, int nargs, const DWORD *args, CSAVE *s);
__asm__(
    ".text\n.globl _check_call\n_check_call:\n"
    "  pushl %ebp\n  movl %esp, %ebp\n  pushl %ebx\n  pushl %esi\n  pushl %edi\n"
    "  movl 20(%ebp), %eax\n"
    "  movl %ebp, 28(%eax)\n  movl %esp, 32(%eax)\n"
    "  movl %eax, %fs:0x14\n"
    "  movl 12(%ebp), %ecx\n  movl 16(%ebp), %edx\n"
    "1: testl %ecx, %ecx\n  jz 2f\n  pushl -4(%edx,%ecx,4)\n  decl %ecx\n  jmp 1b\n"
    "2: movl %esp, 0(%eax)\n"
    "  movl 8(%ebp), %eax\n"
    "  movl $0x5EB05EB0, %ebx\n  movl $0x51515151, %esi\n  movl $0xED1ED1ED, %edi\n  movl $0xEBEBEBE8, %ebp\n"
    "  call *%eax\n"
    "  movl %fs:0x14, %ecx\n"
    "  movl %esp, 4(%ecx)\n  movl %ebx, 8(%ecx)\n  movl %esi, 12(%ecx)\n  movl %edi, 16(%ecx)\n  movl %ebp, 20(%ecx)\n"
    "  movl %eax, 24(%ecx)\n"
    "  movl 28(%ecx), %ebp\n  movl 32(%ecx), %esp\n"
    "  xorl %eax, %eax\n"
    "  movl 0(%ecx), %edx\n  movl 12(%ebp), %ebx\n  leal (%edx,%ebx,4), %edx\n  cmpl 4(%ecx), %edx\n  jne 3f\n"
    "  cmpl $0x5EB05EB0, 8(%ecx)\n  jne 3f\n  cmpl $0x51515151, 12(%ecx)\n  jne 3f\n"
    "  cmpl $0xED1ED1ED, 16(%ecx)\n  jne 3f\n  cmpl $0xEBEBEBE8, 20(%ecx)\n  jne 3f\n"
    "  jmp 4f\n"
    "3: movl $1, %eax\n"
    "4: popl %edi\n  popl %esi\n  popl %ebx\n  popl %ebp\n  ret\n");

typedef struct { const char *name; FARPROC fn; int nargs; int a1kind; DWORD a2; } FN;
static FN g_fn[16]; static int g_nfn;
static HWND g_wnd, g_child; static HDC g_sdc;
static volatile LONG g_stop, g_mem_on, g_calls, g_bad;
static volatile LONG g_badfn[16];
static FILE *g_log;
static CRITICAL_SECTION g_cs;

static void logf(const char *fmt, ...)
{
    va_list a; char b[512];
    va_start(a, fmt); _vsnprintf(b, sizeof(b) - 1, fmt, a); va_end(a); b[sizeof(b) - 1] = 0;
    EnterCriticalSection(&g_cs);
    fputs(b, stdout); if (g_log) { fputs(b, g_log); fflush(g_log); }
    LeaveCriticalSection(&g_cs);
}

static void add(const char *dll, const char *n, int nargs, int a1kind, DWORD a2)
{
    FARPROC f = GetProcAddress(GetModuleHandleA(dll), n);
    if (!f) return;
    g_fn[g_nfn].name = n; g_fn[g_nfn].fn = f; g_fn[g_nfn].nargs = nargs; g_fn[g_nfn].a1kind = a1kind; g_fn[g_nfn].a2 = a2; g_nfn++;
}

static DWORD WINAPI worker(LPVOID p)
{
    CSAVE s; DWORD args[2]; int k = (int)(INT_PTR)p, i;
    while (!g_stop) {
        for (i = 0; i < g_nfn && !g_stop; i++) {
            FN *f = &g_fn[(i + k) % g_nfn];
            args[0] = f->a1kind == 0 ? (DWORD)(ULONG_PTR)g_child : f->a1kind == 1 ? (DWORD)(ULONG_PTR)g_wnd : (DWORD)(ULONG_PTR)g_sdc;
            args[1] = f->a2;
            memset(&s, 0, sizeof(s));
            if (check_call((void *)f->fn, f->nargs, args, &s)) {
                LONG n = InterlockedIncrement(&g_bad);
                InterlockedIncrement(&g_badfn[(i + k) % g_nfn]);
                if (n <= 40) {
                    logf("  BAD %-16s thread %d: ESP moved %ld (should %d)  EBX %08lx ESI %08lx EDI %08lx EBP %08lx  ret %08lx\n",
                         f->name, k, (long)(s.esp_after - s.esp_before), 4 * f->nargs, s.ebx, s.esi, s.edi, s.ebp, s.ret);
                }
            }
            InterlockedIncrement(&g_calls);
        }
    }
    return 0;
}

static DWORD WINAPI memchurn(LPVOID p)
{
    DWORD r = 12345;
    (void)p;
    while (!g_stop) {
        if (!g_mem_on) { Sleep(20); continue; }
        {
            int n = 16 + (int)((r = r * 1103515245 + 12345) >> 16) % 48, k;
            BYTE *m = (BYTE *)VirtualAlloc(NULL, n * 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (m) {
                for (k = 0; k < n; k++) m[k * 4096] = (BYTE)k;
                VirtualFree(m + 4096, 8 * 4096, MEM_DECOMMIT);
                VirtualAlloc(m + 4096, 8 * 4096, MEM_COMMIT, PAGE_READWRITE);
                for (k = 0; k < n; k++) m[k * 4096] ^= 1;
                VirtualFree(m, 0, MEM_RELEASE);
            }
            {
                HANDLE h = GetProcessHeap(); void *a = HeapAlloc(h, 0, 200000);
                if (a) { memset(a, 1, 200000); HeapFree(h, 0, a); }
            }
        }
    }
    return 0;
}

static LRESULT CALLBACK wp(HWND w, UINT m, WPARAM a, LPARAM b) { return DefWindowProcA(w, m, a, b); }

static void phase(const char *name, int threads, int mem, int secs)
{
    HANDLE h[8]; int i; DWORD t0; LONG c0, b0; MSG msg; int step = 0;
    for (i = 0; i < g_nfn; i++) g_badfn[i] = 0;
    c0 = g_calls; b0 = g_bad; g_stop = 0; g_mem_on = mem;
    logf("phase %s: %d worker thread(s)%s, %d s\n", name, threads, mem ? " + memory churn" : "", secs);
    for (i = 0; i < threads; i++) h[i] = CreateThread(NULL, 0, worker, (LPVOID)(INT_PTR)i, 0, NULL);
    t0 = GetTickCount();
    while (GetTickCount() - t0 < (DWORD)secs * 1000) {     /* the window's thread keeps pumping and moving it */
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
        SetWindowPos(g_wnd, NULL, 100 + (step & 15), 100, 300 + (step & 7), 200, SWP_NOZORDER | SWP_NOACTIVATE);
        step++;
        Sleep(10);
    }
    g_stop = 1;
    WaitForMultipleObjects(threads, h, TRUE, 10000);
    for (i = 0; i < threads; i++) CloseHandle(h[i]);
    logf("phase %s result: %ld calls, %ld came back wrong (%.2f per million)\n", name, g_calls - c0, g_bad - b0,
         (g_calls - c0) ? 1e6 * (double)(g_bad - b0) / (double)(g_calls - c0) : 0.0);
    for (i = 0; i < g_nfn; i++) if (g_badfn[i]) logf("    %-18s %ld\n", g_fn[i].name, g_badfn[i]);
}

static LONG WINAPI crashed(EXCEPTION_POINTERS *e)
{
    logf("CRASH: exception %08lx at %08lx (a call returned to a wrong address) - counted so far: %ld calls, %ld wrong\n",
         e->ExceptionRecord->ExceptionCode, (DWORD)(ULONG_PTR)e->ExceptionRecord->ExceptionAddress, g_calls, g_bad);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, char **argv)
{
    WNDCLASSA wc; int secs = argc > 1 ? atoi(argv[1]) : 60; HANDLE mt; SYSTEMTIME t;
    if (secs < 5) secs = 60;
    InitializeCriticalSection(&g_cs);
    SetUnhandledExceptionFilter(crashed);
    g_log = fopen("C:\\THUNKTST.LOG", "a");
    GetLocalTime(&t);
    logf("\n##### THUNKTST %04d-%02d-%02d %02d:%02d:%02d, %d s per phase\n", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, secs);
    memset(&wc, 0, sizeof(wc)); wc.lpfnWndProc = wp; wc.hInstance = GetModuleHandleA(NULL); wc.lpszClassName = "ThunkTst";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassA(&wc);
    g_wnd = CreateWindowA("ThunkTst", "THUNKTST - leave me alone", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 300, 200, NULL, NULL, wc.hInstance, NULL);
    g_child = CreateWindowA("BUTTON", "x", WS_CHILD | WS_VISIBLE, 10, 10, 50, 20, g_wnd, (HMENU)77, wc.hInstance, NULL);
    g_sdc = GetDC(NULL);
    /* a1kind: 0 child window, 1 top window, 2 screen DC */
    add("USER32.DLL", "GetParent", 1, 0, 0);
    add("USER32.DLL", "GetWindow", 2, 0, GW_OWNER);
    add("USER32.DLL", "GetDlgCtrlID", 1, 0, 0);
    add("USER32.DLL", "IsWindowVisible", 1, 1, 0);
    add("USER32.DLL", "GetAncestor", 2, 0, 2);
    add("USER32.DLL", "MonitorFromWindow", 2, 1, 2);
    add("USER32.DLL", "WindowFromDC", 1, 2, 0);
    add("GDI32.DLL", "GetDeviceCaps", 2, 2, 8 /* HORZRES */);
    add("GDI32.DLL", "GetMapMode", 1, 2, 0);
    logf("%d functions, window %08lx child %08lx screen DC %08lx\n", g_nfn, (DWORD)(ULONG_PTR)g_wnd, (DWORD)(ULONG_PTR)g_child, (DWORD)(ULONG_PTR)g_sdc);
    mt = CreateThread(NULL, 0, memchurn, NULL, 0, NULL);
    phase("A", 1, 0, secs);
    phase("B", 4, 0, secs);
    phase("C", 4, 1, secs);
    phase("D", 1, 1, secs);
    g_stop = 1; g_mem_on = 0; InterlockedExchange(&g_stop, 1);
    TerminateThread(mt, 0);
    logf("total: %ld calls, %ld wrong. Log: C:\\THUNKTST.LOG\n", g_calls, g_bad);
    if (g_log) fclose(g_log);
    MessageBoxA(NULL, "THUNKTST finished - results in C:\\THUNKTST.LOG", "THUNKTST", MB_OK);
    return 0;
}
