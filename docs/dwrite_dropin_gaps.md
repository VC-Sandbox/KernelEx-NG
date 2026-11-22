# Windows 10 DLLs as drop-ins on Windows 98 SE + KernelEx + KernelEx-NG

"missing" = static imports nothing provides yet (the DLL will not load). "delay" = delay-load imports (fail only when called). "Nt calls" = direct NT system-call wrappers it imports.

| DLL | imports | missing | delay missing | Nt calls | verdict |
|---|---|---|---|---|---|
| dwrite | 248 | 0 | 0 | 5 | loads now |
| textshaping | 62 | 0 | 0 | 0 | loads now |
