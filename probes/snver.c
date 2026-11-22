/* snver.c - SNVER.EXE <assembly>: the .NET 4 runtime's own strong-name check (clr.dll
 * StrongNameSignatureVerificationEx) on this system, plus StrongNameErrorInfo -> C:\SNVER.TXT. Modern program. */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
typedef BOOL (WINAPI *T_SNV)(LPCWSTR, BOOLEAN, BOOLEAN *);
typedef DWORD (WINAPI *T_SNE)(void);
int main(int argc, char **argv)
{
    FILE *o = fopen("C:\\SNVER.TXT", "w"); WCHAR w[MAX_PATH]; BOOLEAN verified = 0; BOOL r;
    HMODULE c = LoadLibraryA("C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\clr.dll");
    T_SNV v = c ? (T_SNV)GetProcAddress(c, "StrongNameSignatureVerificationEx") : NULL;
    T_SNE e = c ? (T_SNE)GetProcAddress(c, "StrongNameErrorInfo") : NULL;
    fprintf(o, "clr %p verify %p\n", (void *)c, (void *)v); fflush(o);
    if (!v) return 1;
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, w, MAX_PATH);
    r = v(w, TRUE, &verified);
    fprintf(o, "StrongNameSignatureVerificationEx -> %d verified %d error %08lx\n", r, verified, e ? e() : 0);
    {   /* the same file read with ReadFile (no file mapping) -> StrongNameSignatureVerificationFromImage */
        typedef BOOL (WINAPI *T_SNI)(BYTE *, DWORD, DWORD, DWORD *);
        T_SNI vi = (T_SNI)GetProcAddress(c, "StrongNameSignatureVerificationFromImage");
        HANDLE f = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        DWORD sz = GetFileSize(f, NULL), got = 0, of = 0; BYTE *b = (BYTE *)VirtualAlloc(NULL, sz, MEM_COMMIT, PAGE_READWRITE);
        ReadFile(f, b, sz, &got, NULL); CloseHandle(f);
        r = vi ? vi(b, got, 1 /* SN_INFLAG_FORCE_VER */, &of) : 0;
        fprintf(o, "FromImage (ReadFile buffer, %lu bytes) -> %d outflags %lx error %08lx\n", got, r, of, e ? e() : 0);
    }
    fclose(o); return 0;
}
