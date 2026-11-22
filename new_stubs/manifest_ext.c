/* manifest_ext.c - common controls for programs that ask for them in their manifest (build 131).
 *
 * On XP and later a program whose manifest names "Microsoft.Windows.Common-Controls" gets COMCTL32 6 loaded by the
 * loader before its own code runs, and COMCTL32 6 registers every common-control window class when it loads - the
 * program never calls InitCommonControls(Ex). Measured: Pale Moon 35's 7-Zip SFX installer (subsystem 4.0, no
 * COMCTL32 import at all, comctl32 6 manifest) builds its progress dialog (template 97: "msctls_progress32") with
 * DialogBoxParamW; on Windows 98 the class is not registered, the dialog fails, its main thread waits for the
 * extraction thread and that thread waits for the dialog: the installer hangs with no window (SAMPLE.EXE: both
 * threads in WaitForSingleObject at PALEMOON.EXE+1747a).
 * Here: at process start, if the EXE's manifest (resource 24/1, or <exe>.manifest beside it) names that assembly,
 * COMCTL32.DLL is loaded and InitCommonControlsEx registers its classes - what the XP loader causes. Programs without
 * such a manifest (every Windows 98 program) are not touched. */
#include "kexnt_common.h"
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

static BOOL has_cc(const char *p, DWORD n)
{
    static const char k[] = "Microsoft.Windows.Common-Controls"; DWORD i, m = sizeof(k) - 1;
    for (i = 0; i + m <= n; i++) if (!memcmp(p + i, k, m)) return TRUE;
    return FALSE;
}
static BOOL wants_cc(void)
{
    HMODULE exe = GetModuleHandleA(NULL); HRSRC r; int id; char path[MAX_PATH + 16];
    for (id = 1; id <= 3; id++) {
        if ((r = FindResourceA(exe, MAKEINTRESOURCEA(id), MAKEINTRESOURCEA(24))) != NULL) {
            HGLOBAL g = LoadResource(exe, r); DWORD n = SizeofResource(exe, r); const char *p = g ? (const char *)LockResource(g) : NULL;
            if (p && n && has_cc(p, n)) return TRUE;
        }
    }
    {   DWORD n = GetModuleFileNameA(exe, path, MAX_PATH); HANDLE f; char buf[8192]; DWORD got = 0;
        if (!n || n >= MAX_PATH) return FALSE;
        lstrcatA(path, ".manifest");
        f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (f == INVALID_HANDLE_VALUE) return FALSE;
        ReadFile(f, buf, sizeof(buf), &got, NULL); CloseHandle(f);
        return got && has_cc(buf, got);
    }
}
void kex_manifest_comctl(void)
{
    typedef struct { DWORD size, icc; } ICCX;
    typedef BOOL (WINAPI *T_ICCX)(const ICCX *); typedef void (WINAPI *T_ICC)(void);
    static LONG done; HMODULE cc; T_ICCX ix; ICCX i;
    if (InterlockedExchange(&done, 1) || !wants_cc()) return;
    if (!(cc = LoadLibraryA("COMCTL32.DLL"))) return;
    ix = (T_ICCX)(void *)GetProcAddress(cc, "InitCommonControlsEx");
    i.size = sizeof(i); i.icc = 0x3FFF;                 /* every class COMCTL32 5.8 knows (ICC_WIN95..LINK) */
    if (!ix || !ix(&i)) {
        i.icc = 0x00FF;                                  /* older COMCTL32: the classes it has */
        if (!ix || !ix(&i)) { T_ICC ic = (T_ICC)(void *)GetProcAddress(cc, "InitCommonControls"); if (ic) ic(); }
    }
    kex_trace("manifest asks for Common-Controls: COMCTL32 classes registered", (DWORD)(ULONG_PTR)cc, i.icc, 0, 0);
}
