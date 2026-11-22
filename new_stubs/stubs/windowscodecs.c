/* windowscodecs.dll (WIC) for Windows 98 SE (build 131): Firefox 160 imports WICConvertBitmapSource. No WIC on 98. */
#include <windows.h>
HRESULT WINAPI WICConvertBitmapSource(const GUID * fmt, void *src, void **dst) { if (dst) *dst = NULL; return (HRESULT)0x80004001L; }
