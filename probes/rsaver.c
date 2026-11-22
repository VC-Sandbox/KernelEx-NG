/* rsaver.c - RSAVER.EXE: can this system's CryptoAPI verify a 1024-bit RSA / SHA-1 signature (what the .NET strong
 * name check does)? Each provider, each step -> C:\RSAVER.TXT. Key/signature/data made on the host (snvec.h). */
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "snvec.h"
__declspec(dllexport) int KexNG_ModernProcess = 1;
static void test(FILE *o, LPCSTR prov, DWORD type)
{
    HCRYPTPROV p = 0; HCRYPTKEY k = 0; HCRYPTHASH h = 0; BOOL r;
    SetLastError(0); r = CryptAcquireContextA(&p, NULL, prov, type, CRYPT_VERIFYCONTEXT);
    fprintf(o, "[%s type %lu] acquire %d err %lx", prov ? prov : "(default)", type, r, r ? 0 : GetLastError());
    if (!r) { fprintf(o, "\n"); return; }
    r = CryptImportKey(p, g_blob, sizeof(g_blob), 0, 0, &k); fprintf(o, " | import %d err %lx", r, r ? 0 : GetLastError());
    r = CryptCreateHash(p, CALG_SHA1, 0, 0, &h); fprintf(o, " | sha1 %d err %lx", r, r ? 0 : GetLastError());
    if (h) { CryptHashData(h, g_data, sizeof(g_data), 0);
             r = CryptVerifySignatureA(h, g_sig, sizeof(g_sig), k, NULL, 0); fprintf(o, " | VERIFY-A %d err %lx", r, r ? 0 : GetLastError());
             r = CryptVerifySignatureW(h, g_sig, sizeof(g_sig), k, NULL, 0); fprintf(o, " | VERIFY-W %d err %lx", r, r ? 0 : GetLastError()); }
    fprintf(o, "\n");
    if (h) CryptDestroyHash(h); if (k) CryptDestroyKey(k); CryptReleaseContext(p, 0);
}
int main(void)
{
    FILE *o = fopen("C:\\RSAVER.TXT", "w");
    test(o, NULL, PROV_RSA_FULL);
    test(o, MS_DEF_PROV_A, PROV_RSA_FULL);
    test(o, MS_ENHANCED_PROV_A, PROV_RSA_FULL);
    test(o, MS_STRONG_PROV_A, PROV_RSA_FULL);
    test(o, MS_ENH_RSA_AES_PROV_A, 24 /* PROV_RSA_AES */);
    test(o, NULL, 24);
    fclose(o); return 0;
}
