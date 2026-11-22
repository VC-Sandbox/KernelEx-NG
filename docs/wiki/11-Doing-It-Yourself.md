# 11. Doing this yourself

A condensed version of the method, for anyone who wants to build a compatibility layer, for Windows 98 or for any
old system.

## 1. Find a hook point you do not have to rebuild

Rewriting a loader is a project in itself. KernelEx already owned import resolution. A plugin (an API library)
gave this project full control over which function each program gets, without touching KernelEx's core. Look for
the equivalent first: a shim engine, a loader hook, `LD_PRELOAD`, an import table you can redirect.

## 2. Measure the gap, do not guess it

- Dump the imports of the programs you care about and compare them with the target system's exports, plus what
  the base layer adds. This project's scanners (`tools/re_scripts/`) produced the first Chromium list: 409 missing
  functions out of 1,341 imported.
- Ask the real resolver, not your expectation (`GPA.EXE`). Configuration, version mode and load order all change
  the answer.
- Repeat after every fix. The next missing function only appears once the previous one exists.

## 3. Use the real data of the newer system as your table

API-set contents, which DLL exports which name, structure layouts: take them from the newer system's own binaries
and public headers, with generators, never by hand. Hand-written tables were wrong in this project more than once,
for example SRW locks listed in the wrong API set.

## 4. Implement in this order of preference

1. Call the old system's function when its semantics really match.
2. Emulate NT's *documented* contract on top of what the old system has.
3. Fail exactly as the newer system fails when the feature is absent.

Never succeed with garbage.

## 5. Behaviour differences are the real work

Missing functions show up as clear error messages. Differences in behaviour show up as crashes in unrelated code,
days later. For every one you find, write the smallest probe program that shows the difference on the real old
system. Then emulate the newer behaviour, only for programs that expect it.

## 6. Leave old programs alone, by construction

Decide per process whether the new layer applies (here: the EXE's subsystem version), and make that the first
thing every entry point checks. A compatibility layer that breaks the programs the system was made for is a
regression, not progress.

## 7. Build your own instruments early

On an old system without modern debuggers, the most valuable code you write is diagnostic:
- an in-process crash logger;
- a hang dump that names what every thread waits for;
- a sampling profiler;
- a self-test with hundreds of checks;
- an automated VM you can drive from scripts.

They pay for themselves on the first hard bug.

## 8. Prove the cause, then fix

For each bug, write down:
- the symptom;
- the evidence;
- the proven cause;
- the fix;
- the test that would have caught it.

If you cannot name the evidence, you are guessing. The [case studies](09-Case-Studies.md) are examples of this
written out.

## 9. Respect the boundaries

- Do not redistribute the vendor's binaries; let users bring their own.
- Do not copy disassembled vendor code. Learn *where* to hook from disassembly, and *what* to do from
  documentation and measurement.
- Do not patch the programs you are trying to run. Fix the platform underneath them.
