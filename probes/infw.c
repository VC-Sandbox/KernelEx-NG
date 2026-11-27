/* infw.c - probe: can Windows 98's SETUPAPI open the .NET 3.5 setup's UTF-16 setup.sdb (an INF) the way SITSETUP.DLL
 * does (LoadLibrary setupapi.dll + GetProcAddress SetupOpenInfFileW, SetupFindFirstLineW, SetupGetStringFieldW)?
 * Also: the same text as an ANSI copy through the A functions.   INFW.EXE out.txt file.sdb */
#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
typedef HINF (WINAPI *T_OIW)(PCWSTR, PCWSTR, DWORD, PUINT);
typedef HINF (WINAPI *T_OIA)(PCSTR, PCSTR, DWORD, PUINT);
typedef BOOL (WINAPI *T_FFLW)(HINF, PCWSTR, PCWSTR, PINFCONTEXT);
typedef BOOL (WINAPI *T_FFLA)(HINF, PCSTR, PCSTR, PINFCONTEXT);
typedef BOOL (WINAPI *T_GSFW)(PINFCONTEXT, DWORD, PWSTR, DWORD, PDWORD);
typedef BOOL (WINAPI *T_GSFA)(PINFCONTEXT, DWORD, PSTR, DWORD, PDWORD);
int main(int argc, char **argv)
{
    FILE *o; HMODULE h; char sys[MAX_PATH]; WCHAR w[MAX_PATH], b[512]; char a[512]; UINT el = 0; HINF inf; INFCONTEXT c; DWORD n = 0;
    T_OIW oiw; T_OIA oia; T_FFLW fflw; T_FFLA ffla; T_GSFW gsfw; T_GSFA gsfa;
    if (argc < 3 || !(o = fopen(argv[1], "w"))) return 1;
    GetSystemDirectoryA(sys, MAX_PATH); lstrcatA(sys, "\\setupapi.dll");
    h = LoadLibraryA(sys);
    fprintf(o, "LoadLibrary %s: %p\n", sys, (void *)h);
    if (!h) return 2;
    oiw = (T_OIW)GetProcAddress(h, "SetupOpenInfFileW"); oia = (T_OIA)GetProcAddress(h, "SetupOpenInfFileA");
    fflw = (T_FFLW)GetProcAddress(h, "SetupFindFirstLineW"); ffla = (T_FFLA)GetProcAddress(h, "SetupFindFirstLineA");
    gsfw = (T_GSFW)GetProcAddress(h, "SetupGetStringFieldW"); gsfa = (T_GSFA)GetProcAddress(h, "SetupGetStringFieldA");
    fprintf(o, "W: open %p first %p field %p   A: open %p first %p field %p\n", (void *)oiw, (void *)fflw, (void *)gsfw, (void *)oia, (void *)ffla, (void *)gsfa);
    MultiByteToWideChar(CP_ACP, 0, argv[2], -1, w, MAX_PATH);
    if (oiw) {
        SetLastError(0);
        inf = oiw(w, NULL, INF_STYLE_WIN4, &el);
        fprintf(o, "SetupOpenInfFileW(WIN4): %p err %lu line %u\n", (void *)inf, GetLastError(), el);
        if (inf != INVALID_HANDLE_VALUE && fflw && gsfw) {
            BOOL r = fflw(inf, L"Version", L"Provider", &c);
            fprintf(o, "  FindFirstLineW Version/Provider: %d err %lu\n", r, GetLastError());
            if (r) { r = gsfw(&c, 1, b, 512, &n); fprintf(o, "  GetStringFieldW: %d %ls\n", r, r ? b : L""); }
        }
    }
    {   /* ANSI copy of the file */
        HANDLE f = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); DWORD sz, got; BYTE *buf; char *ab; int an;
        if (f != INVALID_HANDLE_VALUE) {
            sz = GetFileSize(f, NULL); buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sz + 2); ReadFile(f, buf, sz, &got, NULL); CloseHandle(f);
            ab = (char *)HeapAlloc(GetProcessHeap(), 0, sz);
            an = WideCharToMultiByte(CP_ACP, 0, (WCHAR *)(buf + 2), (got - 2) / 2, ab, sz, NULL, NULL);
            f = CreateFileA("C:\\INFA.INF", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL); WriteFile(f, ab, an, &got, NULL); CloseHandle(f);
            if (oia) {
                SetLastError(0);
                inf = oia("C:\\INFA.INF", NULL, INF_STYLE_WIN4, &el);
                fprintf(o, "SetupOpenInfFileA(ANSI copy): %p err %lu line %u\n", (void *)inf, GetLastError(), el);
                if (inf != INVALID_HANDLE_VALUE && ffla && gsfa) {
                    BOOL r = ffla(inf, "Version", "Provider", &c);
                    fprintf(o, "  FindFirstLineA: %d err %lu\n", r, GetLastError());
                    if (r) { r = gsfa(&c, 1, a, 512, &n); fprintf(o, "  GetStringFieldA: %d %s\n", r, r ? a : ""); }
                    r = ffla(inf, "VS Custom", "EmptyClient", &c);
                    fprintf(o, "  FindFirstLineA VS Custom/EmptyClient: %d\n", r);
                }
            }
        }
    }
    fclose(o);
    return 0;
}
