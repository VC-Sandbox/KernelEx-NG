# KernelEx-NG wiki

> **AI-generated project, for learning only.** Everything here — code and documentation — was produced by an AI
> under a person's guidance as a proof of concept. Do not run it on a machine with data you care about.
> See the [README](../../README.md).

This wiki explains how KernelEx-NG makes programs built for Windows 10 start on Windows 98 SE. It covers what was
built, how each part works, and **why** it was done that way. It is written to teach: if you wanted to build a
compatibility layer like this yourself, these pages should show you the road, including the dead ends.

## Read in this order

1. [Windows 98 vs. Windows NT](01-Windows-98-vs-NT.md): why modern programs cannot run on 98, explained from the
   ground up.
2. [How KernelEx works](02-How-KernelEx-Works.md): the base this project sits on.
3. [KernelEx-NG architecture](03-Architecture.md): the pieces it adds and how a function call reaches them.
4. [Core techniques](04-Core-Techniques.md): the hard problems and their solutions (PEB, exceptions, locks, TLS,
   pipes, shared memory, process ids, ...).
5. [Module reference](05-Module-Reference.md): every source file, what it provides and why it exists.
6. [Design rules and decisions](06-Design-Decisions.md): the rules the project follows, and the reasons.
7. [Build system](07-Build-System.md): how the DLLs, tables and CD image are generated.
8. [Testing and debugging](08-Testing-and-Debugging.md): kextest, the crash/hang/profile logs, the automated VM.
9. [Case studies](09-Case-Studies.md): real bugs, start to finish, showing how each cause was proven.
10. [Status and limitations](10-Status-and-Limitations.md): what works, what does not, and what never can.
11. [Doing this yourself](11-Doing-It-Yourself.md): the method, condensed.

## The idea in one paragraph

Windows 98 and Windows 10 are different operating systems that happen to share the Win32 API's oldest functions.
A modern program calls hundreds of functions that Windows 98 never had: newer locks, newer memory and process
calls, the native NT API in NTDLL. It also expects NT's data structures and NT's rules for things like process
ids, shared memory and file locks. KernelEx (2008–2011) taught Windows 98 how to hand a program a *different*
implementation of a system function than the one Windows exports. KernelEx-NG uses that mechanism to supply
about two thousand more functions, written from public documentation and measured behaviour. It also fixes the
places where Windows 98's behaviour quietly differs from NT's, and makes sure ordinary Windows 98 programs never
notice any of it.

## Glossary

| Term | Meaning |
|---|---|
| **9x** | Windows 95 / 98 / ME: the DOS-based Windows family |
| **NT** | Windows NT / 2000 / XP / Vista / 7 / 8 / 10 / 11: the other Windows family |
| **API** | the functions a program calls in system DLLs (KERNEL32, USER32, ...) |
| **API library** | a KernelEx plugin DLL that supplies function implementations (`kexbases.dll`, `kexnt.dll`, ...) |
| **Shared arena** | Windows 98's address range 0x80000000–0xBFFFFFFF, mapped the same in every process; system DLLs live there |
| **PEB / TEB** | NT's Process / Thread Environment Block, which NT programs read directly through the `fs` register |
| **PDB / TDB** | Windows 98's process / thread database: what sits where NT code expects the PEB/TEB |
| **API set** | `api-ms-win-*.dll`: Windows 7+ virtual DLL names that forward to the real implementation |
| **Gate** | a tiny stub generated per function that decides whether a caller gets kexnt's version or the old one |
| **Profile** | the Windows version KernelEx reports to a program (set on the KernelEx tab) |
| **VxD** | a Windows 9x ring-0 driver |
