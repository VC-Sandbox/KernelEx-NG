/*
 * reloc_ext.c - KernelEx-NG: base relocations of a DLL that Windows 98 moved but did not fix up.
 *
 * 2026-11-01: chrome.dll (277 MB image, preferred base 0x10000000) was loaded at 0x10010000 because one of our
 * own small DLLs sat at the linker default 0x10000000 - and none of its 10 MB of relocations had been applied
 * (code pushed the unrelocated address of the CRT initializer table; the TLS callback array pointer was the
 * preferred-base value). Our DLLs now have their own bases (dll_base.py), so this should not recur for
 * chrome.dll; this is the safety net for any big DLL that still gets moved.
 *
 * Called by the DLL-entry hook (veh_ext.c) just before a DLL loaded through kexnt's LoadLibrary gets
 * DLL_PROCESS_ATTACH. If the module is not at the base its file asks for, up to 64 HIGHLOW fixup sites spread
 * over the relocation table are compared with the file:
 *    memory == file + delta  -> applied by Windows: nothing to do
 *    memory == file          -> not applied
 * Only when every readable sample is "not applied" does kexnt apply the whole table (NT's own algorithm:
 * add delta at every IMAGE_REL_BASED_HIGHLOW site). Mixed results: nothing is touched, it is only logged.
 */
#include "kexnt_common.h"

void kex_crashlog_text(const char *s);      /* crashlog_ext.c */

static void hexs(char *o, DWORD v) { static const char h[] = "0123456789abcdef"; int i; for (i = 7; i >= 0; i--) o[7 - i] = h[(v >> (i * 4)) & 15]; o[8] = 0; }

static BOOL file_dword(HANDLE f, IMAGE_SECTION_HEADER *sh, int ns, DWORD rva, DWORD *out)
{
    int i; DWORD rd = 0;
    for (i = 0; i < ns; i++)
        if (rva >= sh[i].VirtualAddress && rva + 4 <= sh[i].VirtualAddress + sh[i].SizeOfRawData) {
            if (SetFilePointer(f, (LONG)(sh[i].PointerToRawData + rva - sh[i].VirtualAddress), NULL, FILE_BEGIN) == 0xFFFFFFFF) return FALSE;
            return ReadFile(f, out, 4, &rd, NULL) && rd == 4;
        }
    return FALSE;
}

void kex_reloc_check(HMODULE hm, const char *path)
{
    BYTE *h = (BYTE *)hm, hdr[0x400]; IMAGE_NT_HEADERS32 *mnt, *fnt; IMAGE_SECTION_HEADER *sh;
    IMAGE_BASE_RELOCATION *r, *end; HANDLE f; DWORD rd = 0, delta, rva, size, total = 0, step, k = 0;
    int applied = 0, notyet = 0, other = 0, ns; char line[200], a[9], b[9];
    if (!h || !path || IsBadReadPtr(h, 0x400)) return;
    mnt = (IMAGE_NT_HEADERS32 *)(h + *(LONG *)(h + 0x3C));
    if (IsBadReadPtr(mnt, sizeof(*mnt)) || mnt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC) return;
    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    if (!ReadFile(f, hdr, sizeof(hdr), &rd, NULL) || rd != sizeof(hdr) || *(DWORD *)(hdr + 0x3C) > 0x300) { CloseHandle(f); return; }
    fnt = (IMAGE_NT_HEADERS32 *)(hdr + *(DWORD *)(hdr + 0x3C));
    if (fnt->Signature != IMAGE_NT_SIGNATURE || fnt->OptionalHeader.ImageBase == (DWORD)(ULONG_PTR)h) { CloseHandle(f); return; }
    delta = (DWORD)(ULONG_PTR)h - fnt->OptionalHeader.ImageBase;
    sh = IMAGE_FIRST_SECTION(fnt); ns = fnt->FileHeader.NumberOfSections;
    if ((BYTE *)(sh + ns) > hdr + sizeof(hdr)) { CloseHandle(f); return; }
    rva = fnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    size = fnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!rva || !size || IsBadReadPtr(h + rva, size)) { CloseHandle(f); return; }
    r = (IMAGE_BASE_RELOCATION *)(h + rva); end = (IMAGE_BASE_RELOCATION *)(h + rva + size);
    /* count HIGHLOW sites, then sample every step-th */
    { IMAGE_BASE_RELOCATION *q;
      for (q = r; q < end && q->SizeOfBlock >= 8; q = (IMAGE_BASE_RELOCATION *)((BYTE *)q + q->SizeOfBlock)) {
          WORD *e = (WORD *)(q + 1); DWORD n = (q->SizeOfBlock - 8) / 2, i;
          for (i = 0; i < n; i++) if ((e[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) total++;
      } }
    step = total / 64 + 1;
    { IMAGE_BASE_RELOCATION *q;
      for (q = r; q < end && q->SizeOfBlock >= 8; q = (IMAGE_BASE_RELOCATION *)((BYTE *)q + q->SizeOfBlock)) {
          WORD *e = (WORD *)(q + 1); DWORD n = (q->SizeOfBlock - 8) / 2, i;
          for (i = 0; i < n; i++) {
              DWORD site, fv, mv;
              if ((e[i] >> 12) != IMAGE_REL_BASED_HIGHLOW || (k++ % step)) continue;
              site = q->VirtualAddress + (e[i] & 0xFFF);
              if (IsBadReadPtr(h + site, 4) || !file_dword(f, sh, ns, site, &fv)) continue;
              mv = *(DWORD *)(h + site);
              if (mv == fv + delta) applied++; else if (mv == fv) notyet++; else other++;
          }
      } }
    CloseHandle(f);
    hexs(a, fnt->OptionalHeader.ImageBase); hexs(b, (DWORD)(ULONG_PTR)h);

    {
        char *p = line; const char *s;
        for (s = "--- relocated DLL "; *s; ) *p++ = *s++;
        for (s = path; *s && p < line + 120; ) *p++ = *s++;
        for (s = ": file base "; *s; ) *p++ = *s++;
        for (s = a; *s; ) *p++ = *s++;
        for (s = ", loaded at "; *s; ) *p++ = *s++;
        for (s = b; *s; ) *p++ = *s++;
        *p = 0;
        kex_crashlog_text(line);
    }
    if (applied || other || !notyet) {
        char m[96], *p = m; const char *s; hexs(a, applied); hexs(b, notyet + other);
        for (s = "    Windows applied the relocations (samples ok "; *s; ) *p++ = *s++;
        for (s = a; *s; ) *p++ = *s++; for (s = ", other "; *s; ) *p++ = *s++; for (s = b; *s; ) *p++ = *s++;
        *p++ = ')'; *p = 0;
        kex_crashlog_text(m);
        return;
    }
    /* none applied: apply all (block by block, pages made writable meanwhile) */
    {
        DWORD done = 0, fails = 0; IMAGE_BASE_RELOCATION *q;
        for (q = r; q < end && q->SizeOfBlock >= 8; q = (IMAGE_BASE_RELOCATION *)((BYTE *)q + q->SizeOfBlock)) {
            WORD *e = (WORD *)(q + 1); DWORD n = (q->SizeOfBlock - 8) / 2, i, old = 0;
            BYTE *page = h + q->VirtualAddress;
            if (!VirtualProtect(page, 0x1004, PAGE_READWRITE, &old)) { fails++; continue; }
            for (i = 0; i < n; i++)
                if ((e[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) { *(DWORD *)(page + (e[i] & 0xFFF)) += delta; done++; }
            VirtualProtect(page, 0x1004, old, &old);
        }
        hexs(a, done); hexs(b, fails);
        { char m[96], *p = m; const char *s;
          for (s = "    Windows had NOT applied the relocations - kexnt applied "; *s; ) *p++ = *s++;
          for (s = a; *s; ) *p++ = *s++; for (s = " (blocks failed "; *s; ) *p++ = *s++;
          for (s = b; *s; ) *p++ = *s++; *p++ = ')'; *p = 0;
          kex_crashlog_text(m); }
    }
}
