#include <windows.h>
#include <stdio.h>
void *gp_, *ga_, *gn_, *gg_; DWORD r_esi_, r_eax_;
typedef struct { USHORT Length, MaximumLength; PCHAR Buffer; } AS;
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } US;
typedef LONG (WINAPI *T_LGPA)(HMODULE, AS *, ULONG, PVOID *);
typedef LONG (WINAPI *T_LLD)(PWSTR, PULONG, US *, PVOID *);
int main(void)
{
    HMODULE nt = LoadLibraryA("ntdll.dll"); T_LGPA g = (T_LGPA)GetProcAddress(nt, "LdrGetProcedureAddress");
    T_LLD l = (T_LLD)GetProcAddress(nt, "LdrLoadDll");
    FILE *o = fopen("C:\\LDR.TXT", "w"); AS a; PVOID p = 0, h = 0; LONG st; DWORD esi_before, esi_after;
    US u; WCHAR k32[] = L"kernel32.dll";
    fprintf(o, "LdrGetProcedureAddress %p LdrLoadDll %p\n", g, l);
    u.Buffer = k32; u.Length = sizeof(k32) - 2; u.MaximumLength = sizeof(k32);
    st = l(NULL, NULL, &u, &h); fprintf(o, "LdrLoadDll kernel32 %08lx %p\n", st, h);
    a.Buffer = "wcsstr"; a.Length = 6; a.MaximumLength = 7;
    {
      ga_ = &a; gn_ = nt; gp_ = &p; gg_ = (void *)g;
      __asm__ volatile("pushl %%esi\n\tmovl $0x12345678, %%esi\n\tpushl _gp_\n\tpushl $0\n\tpushl _ga_\n\tpushl _gn_\n\tcall *_gg_\n\t"
                       "movl %%esi, _r_esi_\n\tmovl %%eax, _r_eax_\n\tpopl %%esi" ::: "eax", "ecx", "edx", "memory");
      esi_after = r_esi_; st = r_eax_; }
    fprintf(o, "wcsstr %08lx %p esi after %08lx\n", st, p, esi_after);
    { FILE *f = fopen("C:\\PWN.TXT", "r"); char nm[256]; int bad = 0, n = 0;
      while (f && fscanf(f, "%255s", nm) == 1) {
        a.Buffer = nm; a.Length = (USHORT)strlen(nm); a.MaximumLength = a.Length + 1; p = 0;
        ga_ = &a; gn_ = h; gp_ = &p;
        __asm__ volatile("pushl %%esi\n\tmovl $0x12345678, %%esi\n\tpushl _gp_\n\tpushl $0\n\tpushl _ga_\n\tpushl _gn_\n\tcall *_gg_\n\t"
                         "movl %%esi, _r_esi_\n\tmovl %%eax, _r_eax_\n\tpopl %%esi" ::: "eax", "ecx", "edx", "memory");
        n++;
        if (r_esi_ != 0x12345678) { bad++; fprintf(o, "ESI CHANGED %s -> %08lx st %08lx p %p\n", nm, r_esi_, r_eax_, p); fflush(o); }
      }
      fprintf(o, "%d names, %d changed ESI\n", n, bad); }
    a.Buffer = "GetTickCount64"; a.Length = 14;
    st = g(h, &a, 0, &p); fprintf(o, "GetTickCount64 %08lx %p\n", st, p);
    a.Buffer = "InitOnceExecuteOnce"; a.Length = 19;
    st = g(h, &a, 0, &p); fprintf(o, "InitOnceExecuteOnce %08lx %p\n", st, p);
    fclose(o); return 0;
}
