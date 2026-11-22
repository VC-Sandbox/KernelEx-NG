/*
 * taskdlg_ext.c - KernelEx-NG build 132: TaskDialogIndirect / TaskDialog (COMCTL32 6, Vista+) on Windows 98.
 *
 * Measured (K-Lite Codec Pack 20.2, Inno Setup 6.4.2, Setup log): one DLL failed to register, Inno wanted to ask
 * Abort/Retry/Ignore - "TaskDialogMsgBox failed. LoggedTaskDialogMsgBox returned an unexpected value. Assuming Abort."
 * and the whole installation was rolled back. Inno 6.4 shows every message box through TaskDialogIndirect
 * (Shared.TaskDialogFunc.pas DoTaskDialog: no TaskDialogIndirect -> failure -> answer 0 -> Abort); Windows 98's
 * COMCTL32 5.81 has no task dialogs. So any warning ended every Inno 6.4 setup on Windows 98.
 *
 * Here the task dialog is built as an ordinary dialog (DialogBoxIndirectParamW with an in-memory template, Windows 98's
 * own dialog manager): window title, main instruction, content text, the optional icon (TD_*_ICON or a resource),
 * custom buttons (command links become ordinary buttons, stacked), the common buttons (OK/Yes/No/Cancel/Retry/Close)
 * and the verification check box. The callback gets TDN_DIALOG_CONSTRUCTED, TDN_CREATED, TDN_BUTTON_CLICKED (S_FALSE
 * keeps the dialog open, as documented), TDN_VERIFICATION_CLICKED and TDN_DESTROYED. TDM_* messages sent to the dialog
 * are not handled (progress bars, navigation, expanded text, radio buttons, hyperlinks are not shown).
 * Written from the documented TASKDIALOGCONFIG layout. USER32/GDI32 through kex_sysproc (kexnt imports only
 * KERNEL32/ADVAPI32).
 */
#include "kexnt_common.h"

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

#define TDF_ALLOW_DIALOG_CANCELLATION_ 0x0008
#define TDF_VERIFICATION_FLAG_CHECKED_ 0x0100
#define TDCBF_OK_     0x01
#define TDCBF_YES_    0x02
#define TDCBF_NO_     0x04
#define TDCBF_CANCEL_ 0x08
#define TDCBF_RETRY_  0x10
#define TDCBF_CLOSE_  0x20
#define TDN_CREATED_ 0
#define TDN_BUTTON_CLICKED_ 2
#define TDN_DESTROYED_ 5
#define TDN_DIALOG_CONSTRUCTED_ 7
#define TDN_VERIFICATION_CLICKED_ 8
#define ID_VERIFY 0x5F01
#define ID_ICON   0x5F02

typedef HRESULT (CALLBACK *T_TDCB)(HWND, UINT, WPARAM, LPARAM, LONG_PTR);
#pragma pack(push, 1)
typedef struct { int nButtonID; LPCWSTR pszButtonText; } TDBTN;
typedef struct {
    UINT cbSize; HWND hwndParent; HINSTANCE hInstance; DWORD dwFlags; DWORD dwCommonButtons;
    LPCWSTR pszWindowTitle; LPCWSTR pszMainIcon; LPCWSTR pszMainInstruction; LPCWSTR pszContent;
    UINT cButtons; const TDBTN *pButtons; int nDefaultButton;
    UINT cRadioButtons; const TDBTN *pRadioButtons; int nDefaultRadioButton;
    LPCWSTR pszVerificationText; LPCWSTR pszExpandedInformation; LPCWSTR pszExpandedControlText;
    LPCWSTR pszCollapsedControlText; LPCWSTR pszFooterIcon; LPCWSTR pszFooter;
    T_TDCB pfCallback; LONG_PTR lpCallbackData; UINT cxWidth;
} TDCONFIG;
#pragma pack(pop)

typedef INT_PTR (WINAPI *T_DBIP)(HINSTANCE, LPCDLGTEMPLATEW, HWND, DLGPROC, LPARAM);
typedef BOOL (WINAPI *T_EDLG)(HWND, INT_PTR);
typedef int (WINAPI *T_LSW)(HINSTANCE, UINT, LPWSTR, int);
typedef LRESULT (WINAPI *T_SM)(HWND, UINT, WPARAM, LPARAM);
typedef HWND (WINAPI *T_GDI)(HWND, int);
typedef HICON (WINAPI *T_LI)(HINSTANCE, LPCSTR);
typedef UINT (WINAPI *T_IDBC)(HWND, int);
FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */
/* build 132: Windows 98's own ...W USER32 exports are mostly stubs - take KernelEx's implementation (the one a program
 * would get) for the W functions; ANSI ones straight from USER32 */
static FARPROC u32(const char *n)
{
    size_t l = strlen(n);
    if (l && n[l - 1] == 'W') { FARPROC f = kex_prev_impl("USER32.DLL", n); if (f) return f; }
    return kex_sysproc("USER32.DLL", n);
}

typedef struct { const TDCONFIG *c; int pressed; BOOL verify; } TDSTATE;

/* a string field: NULL, a resource id (from hInstance) or text; out = a heap copy or NULL */
static WCHAR *td_str(const TDCONFIG *c, LPCWSTR s)
{
    WCHAR *r; int n;
    if (!s) return NULL;
    if (!((ULONG_PTR)s >> 16)) {
        WCHAR buf[1024]; T_LSW lsw = (T_LSW)(void *)u32("LoadStringW");
        if (!lsw || (n = lsw(c->hInstance, (UINT)(ULONG_PTR)s, buf, 1024)) <= 0) return NULL;
        buf[n] = 0; s = buf;
        if (!(r = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR)))) return NULL;
        memcpy(r, buf, (n + 1) * sizeof(WCHAR)); return r;
    }
    n = lstrlenW(s);
    if (!(r = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR)))) return NULL;
    memcpy(r, s, (n + 1) * sizeof(WCHAR));
    return r;
}
/* rough text height in dialog units for a width of w DLUs (about 4 DLUs per character, 9 per line) */
static int td_lines(const WCHAR *s, int w)
{
    int lines = 1, col = 0, per = w / 4;
    if (!s || !*s) return 0;
    for (; *s; s++) { if (*s == '\n') { lines++; col = 0; } else if (++col > per) { lines++; col = 0; } }
    return lines;
}

/* in-memory DLGTEMPLATE builder */
typedef struct { BYTE *p; int n, cap; } TB;
static void tb_align(TB *t, int a) { while (t->n % a) t->p[t->n++] = 0; }
static void tb_w(TB *t, WORD v) { if (t->n + 2 <= t->cap) { *(WORD *)(t->p + t->n) = v; t->n += 2; } }
static void tb_d(TB *t, DWORD v) { if (t->n + 4 <= t->cap) { *(DWORD *)(t->p + t->n) = v; t->n += 4; } }
static void tb_s(TB *t, const WCHAR *s) { if (s) while (*s) tb_w(t, (WORD)*s++); tb_w(t, 0); }
static void tb_item(TB *t, DWORD style, int x, int y, int cx, int cy, WORD id, WORD cls, const WCHAR *text)
{
    tb_align(t, 4);
    tb_d(t, style | WS_CHILD | WS_VISIBLE); tb_d(t, 0);
    tb_w(t, (WORD)x); tb_w(t, (WORD)y); tb_w(t, (WORD)cx); tb_w(t, (WORD)cy); tb_w(t, id);
    tb_w(t, 0xFFFF); tb_w(t, cls);                           /* 0x80 button, 0x81 edit, 0x82 static */
    tb_s(t, text ? text : L""); tb_w(t, 0);
}

static HRESULT td_cb(TDSTATE *st, HWND h, UINT n, WPARAM w, LPARAM l)
{
    return st->c->pfCallback ? st->c->pfCallback(h, n, w, l, st->c->lpCallbackData) : S_OK;
}
typedef LONG (WINAPI *T_SWL)(HWND, int, LONG);
typedef LONG (WINAPI *T_GWL)(HWND, int);
static INT_PTR CALLBACK td_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    T_GWL gwl = (T_GWL)(void *)u32("GetWindowLongA");
    TDSTATE *st = gwl ? (TDSTATE *)(ULONG_PTR)gwl(h, DWL_USER) : NULL;
    if (m == WM_INITDIALOG) {
        T_SWL swl = (T_SWL)(void *)u32("SetWindowLongA"); T_SM sm = (T_SM)(void *)u32("SendMessageW");
        T_GDI gdi = (T_GDI)(void *)u32("GetDlgItem"); T_LI li = (T_LI)(void *)u32("LoadIconA");
        st = (TDSTATE *)l;
        if (swl) swl(h, DWL_USER, (LONG)(ULONG_PTR)st);
        if (st->c->pszMainIcon && li && sm && gdi) {            /* TD_WARNING_ICON (-1), ERROR (-2), INFORMATION (-3) */
            LPCSTR id = NULL; INT_PTR v = (INT_PTR)(SHORT)(WORD)(ULONG_PTR)st->c->pszMainIcon;
            if (!((ULONG_PTR)st->c->pszMainIcon >> 16)) id = v == -1 ? IDI_EXCLAMATION : v == -2 ? IDI_HAND : v == -3 ? IDI_ASTERISK : v == -4 ? IDI_EXCLAMATION : NULL;
            if (id) sm(gdi(h, ID_ICON), STM_SETICON, (WPARAM)li(NULL, id), 0);
        }
        if ((st->c->dwFlags & TDF_VERIFICATION_FLAG_CHECKED_) && sm && gdi) sm(gdi(h, ID_VERIFY), BM_SETCHECK, BST_CHECKED, 0);
        td_cb(st, h, TDN_DIALOG_CONSTRUCTED_, 0, 0);
        td_cb(st, h, TDN_CREATED_, 0, 0);
        return TRUE;
    }
    if (!st) return FALSE;
    if (m == WM_COMMAND && HIWORD(w) == BN_CLICKED) {
        int id = LOWORD(w);
        if (id == ID_VERIFY) {
            T_IDBC idbc = (T_IDBC)(void *)u32("IsDlgButtonChecked");
            st->verify = idbc && idbc(h, ID_VERIFY) == BST_CHECKED;
            td_cb(st, h, TDN_VERIFICATION_CLICKED_, (WPARAM)st->verify, 0);
            return TRUE;
        }
        if (id == IDCANCEL && !(st->c->dwFlags & TDF_ALLOW_DIALOG_CANCELLATION_) && !(st->c->dwCommonButtons & TDCBF_CANCEL_)) {
            int k; BOOL custom = FALSE;                       /* Esc/close only when cancelling is allowed */
            for (k = 0; k < (int)st->c->cButtons; k++) if (st->c->pButtons[k].nButtonID == IDCANCEL) custom = TRUE;
            if (!custom) return TRUE;
        }
        if (td_cb(st, h, TDN_BUTTON_CLICKED_, (WPARAM)id, 0) == S_FALSE) return TRUE;   /* documented: keep open */
        st->pressed = id;
        { T_EDLG ed = (T_EDLG)(void *)u32("EndDialog"); if (ed) ed(h, id); }
        return TRUE;
    }
    if (m == WM_DESTROY) td_cb(st, h, TDN_DESTROYED_, 0, 0);
    return FALSE;
}

HRESULT KEXAPI kex_TaskDialogIndirect(const TDCONFIG *c, int *pnButton, int *pnRadio, BOOL *pfVerify)
{
    static const struct { DWORD f; int id; const WCHAR *t; } common[] = {
        { TDCBF_OK_, IDOK, L"OK" }, { TDCBF_YES_, IDYES, L"&Yes" }, { TDCBF_NO_, IDNO, L"&No" },
        { TDCBF_RETRY_, IDRETRY, L"&Retry" }, { TDCBF_CANCEL_, IDCANCEL, L"Cancel" }, { TDCBF_CLOSE_, 8 /*IDCLOSE*/, L"&Close" } };
    T_DBIP dbip = (T_DBIP)(void *)u32("DialogBoxIndirectParamW");
    WCHAR *title, *instr, *content, *verify, *btxt[32]; TB t; TDSTATE st; INT_PTR r;
    int W = 260, y = 7, x0, nitems = 0, i, nb = 0, ncust, hInstr, hContent, cmdlinks, bx, defid;
    WORD *pcount;
    if (!c || c->cbSize < sizeof(TDCONFIG) - 4) return E_INVALIDARG;
    if (!dbip) return E_NOTIMPL;
    ncust = c->cButtons > 32 ? 32 : (int)c->cButtons;
    title = td_str(c, c->pszWindowTitle); instr = td_str(c, c->pszMainInstruction);
    content = td_str(c, c->pszContent); verify = td_str(c, c->pszVerificationText);
    for (i = 0; i < ncust; i++) btxt[i] = td_str(c, c->pButtons[i].pszButtonText);
    cmdlinks = (c->dwFlags & 0x0010 /*TDF_USE_COMMAND_LINKS*/) || (c->dwFlags & 0x0020 /*NO_ICON variant*/);
    t.cap = 16384; t.n = 0; t.p = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, t.cap);
    if (!t.p) return E_OUTOFMEMORY;
    x0 = c->pszMainIcon ? 34 : 7;
    hInstr = td_lines(instr, W - x0 - 7) * 9; hContent = td_lines(content, W - x0 - 7) * 9;
    /* header: DLGTEMPLATE + menu, class, title, font */
    tb_d(&t, DS_MODALFRAME | DS_CENTER | DS_SETFONT | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_3DLOOK);
    tb_d(&t, 0);
    pcount = (WORD *)(t.p + t.n); tb_w(&t, 0);
    tb_w(&t, 0); tb_w(&t, 0); tb_w(&t, (WORD)W); tb_w(&t, 0);   /* x, y, cx, cy (cy patched below) */
    tb_w(&t, 0); tb_w(&t, 0); tb_s(&t, title ? title : L""); tb_w(&t, 8); tb_s(&t, L"MS Sans Serif");
    if (c->pszMainIcon) { tb_item(&t, SS_ICON, 7, 7, 20, 20, ID_ICON, 0x82, NULL); nitems++; }
    if (instr) { tb_item(&t, SS_LEFT | SS_NOPREFIX, x0, y, W - x0 - 7, hInstr, 0xFFFF, 0x82, instr); nitems++; y += hInstr + 5; }
    if (content) { tb_item(&t, SS_LEFT | SS_NOPREFIX, x0, y, W - x0 - 7, hContent, 0xFFFF, 0x82, content); nitems++; y += hContent + 6; }
    if (y < 34 && c->pszMainIcon) y = 34;
    defid = c->nDefaultButton;
    if (cmdlinks) {                                           /* command links: one wide button per row */
        for (i = 0; i < ncust; i++) {
            tb_item(&t, (c->pButtons[i].nButtonID == defid ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON) | WS_TABSTOP | BS_LEFT,
                    x0, y, W - x0 - 7, 16, (WORD)c->pButtons[i].nButtonID, 0x80, btxt[i]); nitems++; y += 19;
        }
        y += 3;
    }
    if (verify) { tb_item(&t, BS_AUTOCHECKBOX | WS_TABSTOP, 7, y, W - 14, 12, ID_VERIFY, 0x80, verify); nitems++; y += 16; }
    /* bottom row: custom push buttons (when not command links) then the common buttons, right-aligned */
    {   int ids[40]; const WCHAR *txt[40]; int k;
        if (!cmdlinks) for (i = 0; i < ncust; i++) { ids[nb] = c->pButtons[i].nButtonID; txt[nb++] = btxt[i]; }
        for (k = 0; k < 6; k++) if (c->dwCommonButtons & common[k].f) { ids[nb] = common[k].id; txt[nb++] = common[k].t; }
        if (!nb && !(cmdlinks && ncust)) { ids[nb] = IDOK; txt[nb++] = L"OK"; }   /* documented default: OK */
        if (!defid && nb) defid = ids[0];
        bx = W - 7 - nb * 54 + 4;
        for (k = 0; k < nb; k++) {
            tb_item(&t, (ids[k] == defid ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON) | WS_TABSTOP, bx + k * 54, y, 50, 14, (WORD)ids[k], 0x80, txt[k]);
            nitems++;
        }
        if (nb) y += 14 + 7;
    }
    *pcount = (WORD)nitems;
    *(WORD *)(t.p + 16) = (WORD)y;                            /* DLGTEMPLATE.cy */
    st.c = c; st.pressed = 0; st.verify = (c->dwFlags & TDF_VERIFICATION_FLAG_CHECKED_) != 0;
    r = dbip(c->hInstance, (LPCDLGTEMPLATEW)t.p, c->hwndParent, td_proc, (LPARAM)&st);
    HeapFree(GetProcessHeap(), 0, t.p);
    if (title) HeapFree(GetProcessHeap(), 0, title);
    if (instr) HeapFree(GetProcessHeap(), 0, instr);
    if (content) HeapFree(GetProcessHeap(), 0, content);
    if (verify) HeapFree(GetProcessHeap(), 0, verify);
    for (i = 0; i < ncust; i++) if (btxt[i]) HeapFree(GetProcessHeap(), 0, btxt[i]);
    { static LONG n; if (InterlockedIncrement(&n) <= 10) kex_crashnote("TaskDialogIndirect shown by kexnt (result, button, buttons, flags)", (DWORD)r, (DWORD)st.pressed, (DWORD)nb, c->dwFlags); }
    if (r == -1 || r == 0) return E_FAIL;              /* no dialog was shown: tell the caller (it falls back) */
    if (pnButton) *pnButton = st.pressed ? st.pressed : (int)r;
    if (pnRadio) *pnRadio = c->nDefaultRadioButton;
    if (pfVerify) *pfVerify = st.verify;
    return S_OK;
}

HRESULT KEXAPI kex_TaskDialog(HWND parent, HINSTANCE inst, LPCWSTR title, LPCWSTR instr, LPCWSTR content,
                              DWORD buttons, LPCWSTR icon, int *pnButton)
{
    TDCONFIG c;
    memset(&c, 0, sizeof(c));
    c.cbSize = sizeof(c); c.hwndParent = parent; c.hInstance = inst; c.dwCommonButtons = buttons;
    c.pszWindowTitle = title; c.pszMainInstruction = instr; c.pszContent = content; c.pszMainIcon = icon;
    return kex_TaskDialogIndirect(&c, pnButton, NULL, NULL);
}
