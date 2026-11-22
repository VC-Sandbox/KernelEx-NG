/* KernelEx-NG: operator new/delete for sheet.dll built with MinGW (no C++ runtime library). */
#include <windows.h>
void* operator new(size_t n) { return HeapAlloc(GetProcessHeap(), 0, n ? n : 1); }
void* operator new[](size_t n) { return HeapAlloc(GetProcessHeap(), 0, n ? n : 1); }
void operator delete(void* p) noexcept { if (p) HeapFree(GetProcessHeap(), 0, p); }
void operator delete[](void* p) noexcept { if (p) HeapFree(GetProcessHeap(), 0, p); }
void operator delete(void* p, size_t) noexcept { if (p) HeapFree(GetProcessHeap(), 0, p); }
void operator delete[](void* p, size_t) noexcept { if (p) HeapFree(GetProcessHeap(), 0, p); }
extern "C" void __cxa_pure_virtual() { }

/* No MinGW DLL startup code (it brings a TLS directory, which Windows 98 cannot give a DLL loaded by Explorer):
 * this entry point runs the global constructors (KexLinkage::instance, the tooltip texts) and then DllMain. */
typedef void (*ctor_t)(void);
extern "C" ctor_t __CTOR_LIST__[];
BOOL APIENTRY DllMain(HINSTANCE, DWORD, LPVOID);
extern "C" BOOL WINAPI DllEntry(HINSTANCE h, DWORD why, LPVOID r)
{
	if (why == DLL_PROCESS_ATTACH)
	{
		unsigned long n = (unsigned long) (ULONG_PTR) __CTOR_LIST__[0];
		if (n == (unsigned long) -1)
			for (n = 0; __CTOR_LIST__[n + 1]; n++) ;
		for (unsigned long i = n; i >= 1; i--)
			__CTOR_LIST__[i]();
	}
	return DllMain(h, why, r);
}
/* destructors of globals are not run (the DLL lives until Explorer ends) */
extern "C" int atexit(void (*)(void)) { return 0; }
