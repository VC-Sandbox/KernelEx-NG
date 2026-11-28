/* cryptprov.c - probe: which CryptoAPI provider types/names CryptAcquireContextW accepts on Windows 98 + KernelEx
 * (.NET 2.0 SP2 asks for PROV_RSA_AES on XP and later). CRYPTPROV.EXE > out.txt */
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
static void t(const WCHAR *name, DWORD type)
{
    HCRYPTPROV h = 0; BOOL ok = CryptAcquireContextW(&h, NULL, name, type, CRYPT_VERIFYCONTEXT);
    printf("type %2lu %-50ls -> %s %08lx\n", type, name ? name : L"(default)", ok ? "OK" : "FAIL", ok ? 0 : GetLastError());
    if (ok) CryptReleaseContext(h, 0);
}
static void ta(const char *name, DWORD type)
{
    HCRYPTPROV h = 0; BOOL ok = CryptAcquireContextA(&h, NULL, name, type, CRYPT_VERIFYCONTEXT);
    printf("A type %2lu %-50s -> %s %08lx\n", type, name ? name : "(default)", ok ? "OK" : "FAIL", ok ? 0 : GetLastError());
    if (ok) CryptReleaseContext(h, 0);
}
int main(void)
{
    ta(NULL, PROV_RSA_FULL); ta(NULL, 24); ta("Microsoft Enhanced Cryptographic Provider v1.0", PROV_RSA_FULL);
    ta("Microsoft Enhanced RSA and AES Cryptographic Provider", 24);
    t(NULL, PROV_RSA_FULL); t(NULL, 24 /* PROV_RSA_AES */); t(NULL, PROV_DSS_DH);
    t(L"Microsoft Enhanced Cryptographic Provider v1.0", PROV_RSA_FULL);
    t(L"Microsoft Enhanced RSA and AES Cryptographic Provider", 24);
    t(L"Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)", 24);
    return 0;
}
