/* dpapi_ext.c - CryptProtectData / CryptUnprotectData for Win98 (2026-11-10, build 21).
 *
 * Win98's CRYPT32 forwards these to the Protected Storage service over RPC; on a plain Win98 SE install that
 * raises RPC exception 0x725 (RPC_X_WRONG_STUB_VERSION) and fails. Chromium's os_crypt (cookies, saved
 * passwords, the Local State key: components/os_crypt/async/browser/dpapi_key_provider.cc) then reports
 * "Failed to encrypt: Incompatible version of the RPC stub" and the profile's encrypted storage stays unusable.
 *
 * Replacement, per Windows user: a 256-bit key kept in HKCU\Software\KernelEx-NG\DPAPI ("Key", created with
 * kexnt's random generator on first use), ChaCha20 with a random 96-bit nonce per blob, optional entropy mixed
 * into the key, and an FNV-1a 64 check value so wrong data / wrong entropy is refused.
 * Blob: "KXDP1\0" | nonce[12] | ChaCha20(plaintext | check[8]).
 * Win98 profiles are not access-controlled, so this protects as much as the platform can (as on NT, the user's
 * own programs can always unprotect). Blobs made by real Windows DPAPI cannot be read here.
 */
#include "kexnt_common.h"
#include <string.h>

BOOL KEXAPI kex_KexGenRandom(PVOID buf, SIZE_T len);            /* sysdll_ext.c */
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

typedef struct { DWORD cbData; BYTE *pbData; } K_BLOB;
#define K_CRYPTPROTECT_UI_FORBIDDEN 0x1
static const BYTE g_magic[6] = { 'K', 'X', 'D', 'P', '1', 0 };

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) (a += b, d ^= a, d = ROTL(d, 16), c += d, b ^= c, b = ROTL(b, 12), \
                        a += b, d ^= a, d = ROTL(d, 8),  c += d, b ^= c, b = ROTL(b, 7))
static void chacha_block(const DWORD key[8], const DWORD nonce[3], DWORD counter, BYTE out[64])
{
    DWORD s[16], x[16]; int i;
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (i = 0; i < 8; i++) s[4 + i] = key[i];
    s[12] = counter; s[13] = nonce[0]; s[14] = nonce[1]; s[15] = nonce[2];
    for (i = 0; i < 16; i++) x[i] = s[i];
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]); QR(x[1], x[5], x[9], x[13]); QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]); QR(x[2], x[7], x[8], x[13]); QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; i++) { DWORD v = x[i] + s[i]; out[4 * i] = (BYTE)v; out[4 * i + 1] = (BYTE)(v >> 8); out[4 * i + 2] = (BYTE)(v >> 16); out[4 * i + 3] = (BYTE)(v >> 24); }
}
static void chacha_xor(const DWORD key[8], const DWORD nonce[3], BYTE *p, DWORD n)
{
    BYTE ks[64]; DWORD ctr = 1, i;
    while (n) {
        DWORD k = n < 64 ? n : 64;
        chacha_block(key, nonce, ctr++, ks);
        for (i = 0; i < k; i++) p[i] ^= ks[i];
        p += k; n -= k;
    }
    SecureZeroMemory(ks, sizeof(ks));
}

static unsigned __int64 fnv64(const BYTE *p, DWORD n, unsigned __int64 h)
{
    while (n--) { h ^= *p++; h *= 0x100000001B3ULL; }
    return h;
}

/* the user's key, mixed with the optional entropy */
static BOOL user_key(DWORD key[8], const K_BLOB *entropy)
{
    HKEY k; DWORD t, n = 32; BYTE raw[32]; BOOL ok = FALSE; int i;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\KernelEx-NG\\DPAPI", 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExA(k, "Key", NULL, &t, raw, &n) == ERROR_SUCCESS && t == REG_BINARY && n == 32) ok = TRUE;
    else if (kex_KexGenRandom(raw, 32) && RegSetValueExA(k, "Key", 0, REG_BINARY, raw, 32) == ERROR_SUCCESS) ok = TRUE;
    RegCloseKey(k);
    if (!ok) return FALSE;
    for (i = 0; i < 8; i++) key[i] = (DWORD)raw[4 * i] | ((DWORD)raw[4 * i + 1] << 8) | ((DWORD)raw[4 * i + 2] << 16) | ((DWORD)raw[4 * i + 3] << 24);
    if (entropy && entropy->cbData && entropy->pbData) {
        unsigned __int64 h = 0xCBF29CE484222325ULL;
        for (i = 0; i < 8; i++) {
            h = fnv64(entropy->pbData, entropy->cbData, h ^ (unsigned __int64)(i + 1) * 0x9E3779B97F4A7C15ULL);
            key[i] ^= (DWORD)(h ^ (h >> 32));
        }
    }
    SecureZeroMemory(raw, sizeof(raw));
    return TRUE;
}

BOOL KEXAPI kex_CryptProtectData(K_BLOB *in, LPCWSTR desc, K_BLOB *entropy, PVOID reserved, PVOID prompt, DWORD flags, K_BLOB *out)
{
    DWORD key[8], nonce[3], n; BYTE *b; unsigned __int64 chk;
    (void)desc; (void)reserved; (void)prompt; (void)flags;
    if (!in || !out || (in->cbData && !in->pbData) || in->cbData > 0x7FFFFF00UL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    out->cbData = 0; out->pbData = NULL;
    if (!user_key(key, entropy) || !kex_KexGenRandom(nonce, sizeof(nonce))) { SetLastError(NTE_BAD_KEY_STATE); return FALSE; }
    n = sizeof(g_magic) + 12 + in->cbData + 8;
    if (!(b = (BYTE *)LocalAlloc(LMEM_FIXED, n))) { SecureZeroMemory(key, sizeof(key)); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    memcpy(b, g_magic, sizeof(g_magic));
    memcpy(b + 6, nonce, 12);
    if (in->cbData) memcpy(b + 18, in->pbData, in->cbData);
    chk = fnv64(in->pbData, in->cbData, 0xCBF29CE484222325ULL);
    memcpy(b + 18 + in->cbData, &chk, 8);
    chacha_xor(key, nonce, b + 18, in->cbData + 8);
    SecureZeroMemory(key, sizeof(key));
    out->cbData = n; out->pbData = b;
    return TRUE;
}

BOOL KEXAPI kex_CryptUnprotectData(K_BLOB *in, LPWSTR *desc, K_BLOB *entropy, PVOID reserved, PVOID prompt, DWORD flags, K_BLOB *out)
{
    DWORD key[8], nonce[3], n; BYTE *b; unsigned __int64 chk, want;
    (void)reserved; (void)prompt; (void)flags;
    if (desc) *desc = NULL;
    if (!in || !out || !in->pbData) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    out->cbData = 0; out->pbData = NULL;
    if (in->cbData < 18 + 8 || memcmp(in->pbData, g_magic, sizeof(g_magic))) {
        static LONG once;
        if (InterlockedIncrement(&once) <= 5) kex_trace("CryptUnprotectData: not a KernelEx-NG blob (made by Windows DPAPI?)", in->cbData, 0, 0, 0);
        SetLastError(ERROR_INVALID_DATA); return FALSE;
    }
    if (!user_key(key, entropy)) { SetLastError(NTE_BAD_KEY_STATE); return FALSE; }
    memcpy(nonce, in->pbData + 6, 12);
    n = in->cbData - 18;
    if (!(b = (BYTE *)LocalAlloc(LMEM_FIXED, n))) { SecureZeroMemory(key, sizeof(key)); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    memcpy(b, in->pbData + 18, n);
    chacha_xor(key, nonce, b, n);
    SecureZeroMemory(key, sizeof(key));
    n -= 8;
    memcpy(&want, b + n, 8);
    chk = fnv64(b, n, 0xCBF29CE484222325ULL);
    if (chk != want) { SecureZeroMemory(b, n + 8); LocalFree(b); SetLastError(ERROR_INVALID_DATA); return FALSE; }
    SecureZeroMemory(b + n, 8);
    if (desc) {                                   /* empty description, LocalAlloc'd as on Windows */
        WCHAR *d = (WCHAR *)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, sizeof(WCHAR));
        *desc = d;
    }
    out->cbData = n; out->pbData = b;
    return TRUE;
}
