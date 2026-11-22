/* cacq.c - CACQ.EXE <out>: CryptAcquireContextW flag/provider combinations and hash algorithms (NT 5.1 program) */
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); DWORD types[] = { PROV_RSA_FULL, 24 /* PROV_RSA_AES */ };
    DWORD flags[] = { CRYPT_VERIFYCONTEXT, CRYPT_VERIFYCONTEXT | 0x40 /* CRYPT_SILENT */ }; ALG_ID algs[] = { CALG_MD5, CALG_SHA1, 0x800c /* SHA_256 */ };
    int t, f, a;
    for (t = 0; t < 2; t++) for (f = 0; f < 2; f++) {
        HCRYPTPROV p = 0; BOOL b = CryptAcquireContextW(&p, NULL, NULL, types[t], flags[f]);
        fprintf(o, "type %lu flags %08lx -> %d err %08lx\n", types[t], flags[f], b, b ? 0 : GetLastError());
        if (b) { for (a = 0; a < 3; a++) { HCRYPTHASH h = 0; BOOL c = CryptCreateHash(p, algs[a], 0, 0, &h);
                 fprintf(o, "   hash %04x -> %d err %08lx\n", algs[a], c, c ? 0 : GetLastError()); if (c) CryptDestroyHash(h); }
                 CryptReleaseContext(p, 0); }
    }
    fclose(o); return 0;
}
