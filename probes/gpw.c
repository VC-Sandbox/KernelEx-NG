#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); int i;
    HMODULE k = GetModuleHandleW(L"kernel32"), k2 = LoadLibraryW(L"kernel32"), k3 = LoadLibraryA("kernel32");
    fprintf(o, "GetModuleHandleW(kernel32) %p LoadLibraryW %p LoadLibraryA %p\n", (void *)k, (void *)k2, (void *)k3);
    for (i = 2; i < argc; i++) fprintf(o, "%s %p\n", argv[i], (void *)GetProcAddress(k3, argv[i]));
    fclose(o); return 0;
}
