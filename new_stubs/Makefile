# KernelEx-NG Phase 1 - cross-compile for i386 Win32 (Windows 98 SE) with MinGW-w64.
#   Debian/Ubuntu: sudo apt install gcc-mingw-w64-i686 binutils-mingw-w64-i686
#   Windows host : MSYS2 "mingw32" shell: pacman -S mingw-w64-i686-gcc make
# make            -> build/kexnt.dll + build/api-ms-win-*.dll
# make check      -> list exports of every built DLL (objdump)
CROSS   ?= i686-w64-mingw32-
CC      := $(CROSS)gcc
OBJDUMP := $(CROSS)objdump
NM      := $(CROSS)nm
DLLTOOL := $(CROSS)dlltool
# i686 baseline (Pentium Pro+); no SSE in our own code so the layer runs on any 9x-era CPU.
# -fno-stack-protector/-nostdlib-like options keep msvcrt-only imports that exist on Win98.
CFLAGS  := -O2 -march=i686 -mno-sse -D__USE_MINGW_ANSI_STDIO=0 -Wall -Wextra -Wno-unused-parameter -std=gnu99 \
           -fno-strict-aliasing -fno-stack-protector -fno-asynchronous-unwind-tables -D_WIN32_IE=0x0500
LDFLAGS := -shared -static-libgcc -Wl,--enable-stdcall-fixup -Wl,--subsystem,windows:4.0 \
           -Wl,--major-os-version,4 -Wl,--minor-os-version,0 -Wl,--file-alignment,4096 \
           -Wl,--section-alignment,4096 -Wl,--disable-dynamicbase -Wl,--disable-nxcompat \
           -Wl,--enable-reloc-section
# Keep .reloc: Win9x must relocate a DLL when its preferred base is taken (shared arena collisions).
LIBS    := -lkernel32 -ladvapi32
# GCC (MinGW-w64) or clang (llvm-mingw) both work; pick the matching runtime/flags.
IS_CLANG := $(shell $(CC) --version 2>/dev/null | grep -qi clang && echo 1)
ifeq ($(IS_CLANG),1)
LIBGCC     ?= -lclang_rt.builtins-i386
CRT_NOLOOP :=
else
LIBGCC     ?= -lgcc
CRT_NOLOOP := -fno-tree-loop-distribute-patterns
endif

B := build
# Folder with your Win10 SysWOW64 DLLs; ucrtbase.dll from it goes on the (private) test CD
WIN10_DLLS ?=
# Optional UCRT MinGW compiler for tests/ucrttest.c (see the ucrttest rule)
UCRT_CC ?=
UCRTTEST := $(if $(UCRT_CC),$(B)/ucrttest.exe)
# apisets.txt: api-ms-win-core/... -> kexnt/Win98/KernelEx; apisets_crt.txt: api-ms-win-crt-* -> genuine Win10 ucrtbase.dll
APISET_TABLES := apisets.txt apisets_ng.txt $(wildcard apisets_crt.txt)
export APISET_TABLES
APISETS := $(shell awk '!/^\#/ && NF==3 {print $$1}' $(APISET_TABLES) | sort -u)
APISET_DLLS := $(addprefix $(B)/,$(addsuffix .dll,$(APISETS)))

KEXNT_SRCS := kexnt.c chrome_ext.c ntreg_ext.c shm_ext.c sec_ext.c crashlog_ext.c pipe_ext.c sysdll_ext.c ntdll_ext.c kernel32_ext.c sync_ext.c fls_ext.c sysinfo_ext.c locale_ext.c peb_ext.c veh_ext.c loader_ext.c tls_ext.c reloc_ext.c mem_ext.c lockfile_ext.c dirhandle_ext.c ws_ext.c font_ext.c gdiguard_ext.c guard_gen.c prof_ext.c w10_ext.c msvcrt_ext.c proctime_ext.c nttoken_ext.c filever_ext.c secsid_ext.c stubfix_ext.c procspawn_ext.c knowndll_ext.c iocp_ext.c spi_ext.c dpapi_ext.c fview_ext.c wait_ext.c layered_ext.c hang_ext.c fpath_ext.c realos_ext.c filedlg_ext.c memstat_ext.c yield_ext.c res_ext.c gate_ext.c job_ext.c laa_ext.c installer_ext.c msicompat_ext.c fmtmsg_ext.c uini_ext.c actctx_ext.c net_ext.c ntldr_ext.c manifest_ext.c ntcrt_ext.c tpwork_ext.c gecko115_ext.c ntfacade_ext.c pid_ext.c assoc_ext.c taskdlg_ext.c fwdload_pic.c imgsec_ext.c ntcs_ext.c kexnt_crt.c
KEXNT_OBJS := $(addprefix $(B)/,$(KEXNT_SRCS:.c=.o))
HDRS := $(wildcard *.h)
# Win98 SE reference DLLs (extracted from the CD CABs) used by "make verify".
WIN98_DLLS ?= $(HOME)/cd98

all: $(B)/kexnt.dll $(B)/kexver.dll $(APISET_DLLS) $(STUB_DLLS) $(B)/kextest.exe $(B)/vertest.exe $(B)/kexcfg.exe $(B)/kexroute.exe $(B)/kexsetup.exe $(B)/ucrtload.exe $(B)/kexdbg.exe $(B)/keximp.exe $(B)/kxlegacy.exe $(B)/kexdump.exe $(B)/chrvar.exe $(B)/thunktst.exe $(B)/sheet.dll $(B)/psapi.dll $(B)/userenv.dll $(B)/kextls.dll $(B)/kexnotls.dll $(B)/sqltest.exe $(B)/kexaudio.dll $(UCRTTEST)

$(B):
	mkdir -p $@

$(B)/%.o: %.c $(HDRS) | $(B)
	$(CC) $(CFLAGS) -c $< -o $@

# -ffreestanding: stop GCC turning the strlen/strcmp loops back into calls to themselves.
$(B)/kexnt_crt.o: kexnt_crt.c | $(B)
	$(CC) $(CFLAGS) -ffreestanding -fno-builtin $(CRT_NOLOOP) -c $< -o $@

# Export table = every stdcall kex_<Name>@N in the objects, exported as <Name>, plus aliases.
$(B)/kexnt.def: $(KEXNT_OBJS) kexnt_alias.def
	{ echo "LIBRARY kexnt.dll"; echo "EXPORTS"; \
	  $(NM) -g --defined-only $(KEXNT_OBJS) | awk '$$3 ~ /^_kex_.*@[0-9]+$$/ { s = substr($$3, 2); n = s; \
	      sub(/^kex_/, "", n); sub(/@.*/, "", n); printf "    %s=%s\n", n, s }' | sort -u; \
	  grep -v '^;' kexnt_alias.def; echo "    get_api_table"; } > $@

# KernelEx api-library table (get_api_table): which exports the resolver publishes under KERNEL32/NTDLL.
$(B)/kexnt_apitable.c: $(B)/kexnt.def kexnt_targets.txt kexnt_cdecl.txt gen_apitable.py
	python3 gen_apitable.py $(B)/kexnt.def kexnt_targets.txt kexnt_cdecl.txt > $@

$(B)/kexnt_apitable.o: $(B)/kexnt_apitable.c
	$(CC) $(CFLAGS) -c $< -o $@

# No C runtime (see kexnt_crt.c): entry point is DllMain itself; libgcc only for 64-bit division helpers.
$(B)/kexnt.dll: $(KEXNT_OBJS) $(B)/kexnt_apitable.o $(B)/kexnt.def
	$(CC) $(LDFLAGS) -nostdlib -Wl,-e,_DllMain@12 -Wl,--image-base,0x6A000000 -o $@ $(KEXNT_OBJS) $(B)/kexnt_apitable.o \
	  $(B)/kexnt.def $(LIBS) $(LIBGCC) -Wl,--out-implib,$(B)/libkexnt.a
	@$(CROSS)nm $@ > $(B)/kexnt.nm && python3 check_pic.py $@ $(B)/kexnt.nm || { rm -f $@; exit 1; }
	@if $(OBJDUMP) -p $@ | grep "DLL Name:" | grep -viE "KERNEL32|ADVAPI32"; then \
	  echo "kexnt.dll must import only KERNEL32/ADVAPI32 (see kexnt_crt.c)"; rm -f $@; exit 1; fi
	@# Import library with stdcall-decorated names (Name@N -> export Name): GNU ld does not map __imp__Name@N to an
	@# undecorated import by itself (lld does), so the stub DLLs that import from kexnt link with both toolchains.
	@{ echo "LIBRARY kexnt.dll"; echo "EXPORTS"; awk -F= '/=/ { n = $$1; gsub(/[ \t]/, "", n); at = index($$2, "@"); \
	  print "    " n (at ? substr($$2, at) : "") }' $(B)/kexnt.def; } > $(B)/kexnt_imp.def
	$(DLLTOOL) -k -d $(B)/kexnt_imp.def -D kexnt.dll -l $(B)/libkexnt.a

# KEXVER.DLL: version profiles api library (one implementation per Windows version, picked by core.ini index).
$(B)/kexver.dll: kexver.c $(B)/kexnt_crt.o kexnt_common.h | $(B)
	$(CC) $(CFLAGS) $(LDFLAGS) -nostdlib -Wl,--kill-at -Wl,-e,_DllMain@12 -Wl,--image-base,0x69000000 -o $@ \
	  kexver.c $(B)/kexnt_crt.o -lkernel32 $(LIBGCC)
	@if $(OBJDUMP) -p $@ | grep "DLL Name:" | grep -viE "KERNEL32"; then \
	  echo "kexver.dll must import only KERNEL32"; rm -f $@; exit 1; fi

# Self-test: loads kexnt.dll dynamically and exercises the exports (runs on Win98 or Wine).
$(B)/kextest.exe: tests/kextest.c kexng_build.h | $(B)
	$(CC) -O1 -march=i686 -mno-sse -D__USE_MINGW_ANSI_STDIO=0 -Wall -std=gnu99 -fno-stack-protector -fno-asynchronous-unwind-tables \
	  -Wl,--subsystem,console:4.0 -Wl,--major-os-version,4 -Wl,--minor-os-version,0 -Wl,--large-address-aware -o $@ $< -lole32 -luuid -lversion -lgdi32 -luser32 -ladvapi32 -lkernel32

EXE_FLAGS := -O1 -march=i686 -mno-sse -D__USE_MINGW_ANSI_STDIO=0 -Wall -std=gnu99 -fno-stack-protector -fno-asynchronous-unwind-tables \
  -Wl,--subsystem,console:4.0 -Wl,--major-os-version,4 -Wl,--minor-os-version,0

# SQLite the way Chromium uses it (mmap, exclusive locking, TRUNCATE journal, WAL), NT code path (build 24).
$(B)/sqlite3.o: third_party/sqlite/sqlite3.c | $(B)
	$(CC) -O2 -march=i686 -mno-sse -D__USE_MINGW_ANSI_STDIO=0 -fno-stack-protector -fno-asynchronous-unwind-tables -DSQLITE_WIN32_GETVERSIONEX=0 \
	  -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DEFAULT_MEMSTATUS=0 -w -c $< -o $@
$(B)/sqltest.exe: tests/sqltest.c $(B)/sqlite3.o | $(B)
	$(CC) $(EXE_FLAGS) -Ithird_party/sqlite -o $@ $< $(B)/sqlite3.o -lkernel32

# Routing test: imports Vista+/Win10 names STATICALLY from KERNEL32/NTDLL/api-ms (needs KernelEx + kexnt).
$(B)/kexroute.exe: tests/kexroute.c | $(B)
	$(CC) $(EXE_FLAGS) -o $@ $< -lkernel32 -lntdll -lsynchronization

# Genuine Win10 ucrtbase.dll tests. ucrtload: built against msvcrt, loads ucrtbase.dll dynamically.
$(B)/ucrtload.exe: tests/ucrtload.c | $(B)
	$(CC) $(EXE_FLAGS) -o $@ $< -lkernel32

# ucrttest: linked like a VS2015+ program (imports api-ms-win-crt-*). Needs a UCRT MinGW toolchain:
#   make UCRT_CC=/path/to/llvm-mingw-ucrt/bin/i686-w64-mingw32-gcc
$(B)/ucrttest.exe: tests/ucrttest.c | $(B)
	$(UCRT_CC) $(EXE_FLAGS) -o $@ $< -lkernel32

# vertest: what version a program is told under its KernelEx profile; imports GetTickCount64 from an
# api set so our shells (and the NT PEB emulation) load.
$(B)/vertest.exe: tests/vertest.c | $(B)
	printf 'LIBRARY api-ms-win-core-sysinfo-l1-1-0.dll\nEXPORTS\n    GetTickCount64@0\n' > $(B)/vt_sysinfo.def
	$(DLLTOOL) -k -d $(B)/vt_sysinfo.def -l $(B)/libvt_sysinfo.a
	$(CC) $(EXE_FLAGS) -o $@ $< $(B)/libvt_sysinfo.a -lkernel32

# kexcfg: which core.ini configurations the running KernelEx core actually loaded (+ VEH state).
$(B)/kexcfg.exe: tests/kexcfg.c | $(B)
	$(CC) $(EXE_FLAGS) -o $@ $< -ladvapi32 -lkernel32

# Debugger / crash logger: KEXDBG program args -> KEXDBG.LOG (module map, exceptions, stack).
$(B)/kexdbg.exe: tests/kexdbg.c | $(B)
	$(CC) $(EXE_FLAGS) -o $@ $< -lkernel32

# Import checker: KEXIMP file.dll -> KEXIMP.LOG (which imports cannot be resolved under this KernelEx mode).
$(B)/kxlegacy.exe: tests/kxlegacy.c | $(B)
	$(CC) -O1 -march=i686 -mno-sse -Wall -std=gnu99 -fno-stack-protector -fno-asynchronous-unwind-tables \
	  -Wl,--subsystem,console:4.0 -Wl,--major-os-version,4 -Wl,--minor-os-version,0 -o $@ $< -lkernel32

$(B)/keximp.exe: tests/keximp.c | $(B)
	$(CC) $(EXE_FLAGS) -o $@ $< -lkernel32

# Chrome test-mode launcher (CHRVAR1..4.BAT on the CD).
$(B)/chrvar.exe: tests/chrvar.c kexng_build.h | $(B)
	$(CC) $(EXE_FLAGS) -mwindows -o $@ $< -lkernel32 -luser32 -lgdi32 -ladvapi32 -lwsock32

# KernelEx tab (KernelEx 4.5.2's sheet.dll, ../sheet) built with MinGW; build 58 adds "Report real OS version to
# websites" for browsers. kvec instead of std::vector, own operator new/delete (sheet/ngrt.cpp), no C++ runtime.
SHEET_SRCS := ../sheet/sheet.cpp ../sheet/KexLinkage.cpp ../sheet/server.cpp ../sheet/factory.cpp ../sheet/ngrt.cpp
SHEET_CXXFLAGS := -O2 -march=i686 -mno-sse -fno-exceptions -fno-rtti -fno-stack-protector -fno-asynchronous-unwind-tables \
	-fno-threadsafe-statics -I../sheet -idirafter ../common -D__USE_MINGW_ANSI_STDIO=0 -Dsnprintf=_snprintf -DWIN32 -D_WINDOWS -DNDEBUG -D_WIN32_IE=0x0500 -D_WIN32_WINNT=0x0400 -w
$(B)/sheet.dll: $(SHEET_SRCS) ../sheet/sheet.rc ../sheet/resource.h ../sheet/KexLinkage.h ../sheet/kexcore_min.h ../sheet/server.def | $(B)
	$(CROSS)windres -I../sheet -O coff ../sheet/sheet.rc -o $(B)/sheet_res.o
	$(CROSS)g++ $(SHEET_CXXFLAGS) -shared -s -o $@ $(SHEET_SRCS) $(B)/sheet_res.o ../sheet/server.def -static-libgcc -nostdlib++ -nostartfiles -Wl,-e,_DllEntry@12 \
	  -Wl,--subsystem,windows:4.0 -Wl,--major-os-version,4 -Wl,--minor-os-version,0 -Wl,--disable-dynamicbase -Wl,--disable-nxcompat \
	  -Wl,--enable-reloc-section -lkernel32 -luser32 -lgdi32 -lcomctl32 -ladvapi32 -lshell32 -lshlwapi -lole32 -luuid -lmsvcrt

# build 131: KernelEx's psapi.dll (../auxiliary/psapi/psapi.c, unchanged) + psapi/psapi_ng.c (GetModuleInformation,
# GetMappedFileNameA/W, EnumProcessModulesEx, GetPerformanceInfo -> kexnt's K32 functions). KEXSETUP puts it into the
# KernelEx folder (KernelEx's own kept as PSAPI.ORG).
$(B)/psapi.dll: ../auxiliary/psapi/psapi.c psapi/psapi_ng.c psapi/psapi.def psapi/kernelex.def | $(B)
	$(CROSS)dlltool -d psapi/kernelex.def -l $(B)/libkernelex_psapi.a
	$(CC) -O2 -march=i686 -mno-sse -fno-stack-protector -fno-asynchronous-unwind-tables -Ipsapi -DGetProcessId=_GetProcessId -w -shared -s -o $@ \
	  ../auxiliary/psapi/psapi.c psapi/psapi_ng.c psapi/psapi.def $(B)/libkernelex_psapi.a -nostartfiles -Wl,-e,_DllMain@12 \
	  -Wl,--subsystem,windows:4.0 -Wl,--major-os-version,4 -Wl,--minor-os-version,0 -Wl,--disable-dynamicbase -Wl,--disable-nxcompat \
	  -Wl,--enable-reloc-section -Wl,--image-base,0x7D020000 -lkernel32

# build 131: KernelEx's userenv.dll (../auxiliary/userenv/userenv.c, unchanged) + userenv/userenv_ng.c
# (EnterCriticalPolicySection / LeaveCriticalPolicySection). KEXSETUP: KernelEx folder, original kept as USERENV.ORG.
$(B)/userenv.dll: ../auxiliary/userenv/userenv.c userenv/userenv_ng.c userenv/userenv.def | $(B)
	$(CC) -O2 -march=i686 -mno-sse -fno-stack-protector -fno-asynchronous-unwind-tables -Iuserenv -include userenv/compat.h -w -shared -s -o $@ \
	  ../auxiliary/userenv/userenv.c userenv/userenv_ng.c userenv/userenv.def -Wl,--subsystem,windows:4.0 -Wl,--major-os-version,4 \
	  -Wl,--minor-os-version,0 -Wl,--disable-dynamicbase -Wl,--disable-nxcompat -Wl,--enable-reloc-section -Wl,--image-base,0x7D0A0000 \
	  -lkernel32 -lshell32 -lshlwapi -luser32 -ladvapi32

# Windows 98 USER/GDI thunk return checker (VMware vs 86Box), build 55e.
$(B)/thunktst.exe: tests/thunktst.c | $(B)
	$(CC) $(EXE_FLAGS) -o $@ $< -lkernel32 -luser32 -lgdi32

# Thread dump on request: KEXDUMP -> KEXHANG_<program>.LOG (hang_ext.c).
$(B)/kexdump.exe: tests/kexdump.c | $(B)
	$(CC) $(EXE_FLAGS) -o $@ $< -lkernel32

# Test DLL with a static TLS directory (kextest [TLS DLL]).
$(B)/kextls.dll: tests/kextls.c | $(B)
	$(CC) -O2 -shared -Wl,--subsystem,windows:4.0 -Wl,--major-os-version,4 -Wl,--minor-os-version,0 -Wl,--image-base,0x63000000 -o $@ $<
# Same image base, no TLS: loaded and freed first so kextls.dll reuses its address (build 45).
$(B)/kexnotls.dll: tests/kexnotls.c | $(B)
	$(CC) -O2 -shared -Wl,--subsystem,windows:4.0 -Wl,--major-os-version,4 -Wl,--minor-os-version,0 -Wl,--image-base,0x63000000 -o $@ $<

# KEXAUDIO.DLL: Core Audio (MMDevice API / WASAPI shared mode) over waveOut, registered as CLSID_MMDeviceEnumerator (build 39).
$(B)/kexaudio.dll: audio/kexaudio.c audio/kexaudio.def | $(B)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--image-base,0x6C000000 -o $@ audio/kexaudio.c audio/kexaudio.def -lwinmm -lole32 -luser32 $(LIBS)

# Installs kexnt.dll into an existing KernelEx (core.ini contents=, KnownDLLs, api-ms DLLs).
$(B)/kexsetup.exe: tests/kexsetup.c tests/msroot2001.h kexng_build.h | $(B)
	$(CC) $(EXE_FLAGS) -o $@ $< -ladvapi32 -lkernel32

# Every import of every built binary must exist in the Win98 SE DLLs (or our own DLLs).
verify: all
	python3 ../tools/re_scripts/verify_win98_imports.py --win98 $(WIN98_DLLS) --ours $(B) --kex ../docs/kex_inventory.json $(B)/*.dll $(B)/kextest.exe $(B)/kexsetup.exe
	python3 tests/check_apitable.py $(B)/kexnt.dll

# One .def per API set, generated from apisets.txt (forwarders only + KexApiSetInfo).
# .def/.fwd/.thunks.c per API set (gen_apiset_thunks.py): system-DLL targets become lazy thunks
# (PE forwarders to them bypass KernelEx - see the script), kexnt/ucrtbase targets stay forwarders.
# lld (clang) wrongly decorates forwarder targets in i386 .def files ("_kexnt.Name"), so with
# clang the forwarders go to the linker as -export: options (response file $*.fwd) instead.
$(B)/%.def: $(APISET_TABLES) gen_apiset_thunks.py | $(B)
	python3 gen_apiset_thunks.py $* $(B) "$(IS_CLANG)" $(APISET_TABLES)

# Own image base per small DLL (dll_base.py): not the linker default 0x10000000, which big DLLs want.
SMALL_DLL_NAMES = $(APISETS) $(shell awk '!/^\#/ && NF==3 {print $$1}' stubs/stubs.txt | sort -u | sed 's/\.[^.]*$$//')

$(B)/%.dll: api_sets_shim.c $(B)/%.def kexnt_common.h gen_apiset_deps.sh dll_base.py
	deps=$$(sh gen_apiset_deps.sh $* $(B) $(DLLTOOL)); \
	$(CC) $(CFLAGS) -I. -DAPISET_NAME='"$*"' $(LDFLAGS) -nostartfiles -Wl,-e,_DllMain@12 -Wl,--image-base,$$(python3 dll_base.py $* $(SMALL_DLL_NAMES)) -o $@ api_sets_shim.c $(B)/$*.deps.c $(B)/$*.thunks.c $(B)/$*.def \
	  $(if $(filter 1,$(IS_CLANG)),@$(B)/$*.fwd) $$deps $(LIBS)

# Stub DLLs for Windows DLLs absent on Win98 SE (stubs/stubs.txt -> stubs/gen_stubs.py). Stack sizes are
# taken from the MinGW import libraries of the toolchain, which must be the clang/llvm-mingw one.
MINGW_LIBDIR ?= $(dir $(shell command -v $(CC)))../i686-w64-mingw32/lib
SB := $(B)/stubs
$(SB)/decor.txt: | $(B)
	mkdir -p $(SB)
	for f in $(MINGW_LIBDIR)/lib*.a; do $(NM) "$$f" 2>/dev/null | awk '$$2=="T" && $$3 ~ /^_[A-Za-z].*@[0-9]+$$/ {print substr($$3,2)}'; done | sort -u > $@

$(SB)/stub_dlls.txt: stubs/stubs.txt stubs/gen_stubs.py $(SB)/decor.txt
	python3 stubs/gen_stubs.py stubs/stubs.txt $(SB)/decor.txt $(SB)

STUB_BASES := $(shell awk '!/^\#/ && NF==3 {print $$1}' stubs/stubs.txt | sort -u)
STUB_DLLS := $(addprefix $(SB)/,$(STUB_BASES))

$(SB)/%: $(SB)/stub_dlls.txt stubs/stub_main.c $(wildcard stubs/*.rc) $(B)/kexnt.dll $(B)/kexnt_crt.o dll_base.py
	b=$$(basename $* | sed 's/\.[^.]*$$//' | tr A-Z a-z); res=; \
	if [ -f stubs/$$b.rc ]; then $(CROSS)windres -O coff stubs/$$b.rc -o $(SB)/$$b.res.o && res=$(SB)/$$b.res.o; fi; \
	$(CC) $(CFLAGS) -Wno-unused-parameter -Wno-missing-declarations $(LDFLAGS) -nostdlib -Wl,-e,_DllMain@12 \
	  -Wl,--image-base,$$(python3 dll_base.py $$b $(SMALL_DLL_NAMES)) -o $@ \
	  stubs/stub_main.c $(SB)/$$b.gen.c $$( [ -f stubs/$$b.c ] && echo stubs/$$b.c ) $(SB)/$$b.def $(B)/kexnt_crt.o $$res \
	  $(B)/libkexnt.a -lkernel32 -ladvapi32 -lole32 -lgdi32 -luser32 $(LIBGCC)

stubs: $(STUB_DLLS)
.PHONY: stubs

check: all
	@for f in $(B)/*.dll; do echo "== $$f"; $(OBJDUMP) -p $$f | sed -n '/\[Ordinal\/Name Pointer\] Table/,/^$$/p'; done

# ISO for attaching to the Win98 VM as a CD (VMware or QEMU). xorriso if present, else tools/mkiso.py.
iso: all stubs
	python3 check_nosse.py $(CROSS)objdump $(B)/*.dll $(B)/*.exe   # must run on CPUs without SSE (86Box)
	rm -rf $(B)/iso && mkdir -p $(B)/iso && cp $(B)/*.dll $(B)/*.exe $(STUB_DLLS) $(SB)/stub_dlls.txt $(B)/iso/
	[ -z "$(WIN10_DLLS)" ] || cp $(WIN10_DLLS)/ucrtbase.dll $(B)/iso/   # your own Win10 SysWOW64 copy - private test CD only
	[ -z "$(WIN10_DLLS)" ] || for f in DWrite TextShaping ucrtbase; do [ ! -f $(WIN10_DLLS)/$$f.dll ] || cp $(WIN10_DLLS)/$$f.dll $(B)/iso/$$f.w10; done   # Windows 10 DLLs supplied by the builder (KEXSETUP installs them) - private test CD only
	printf '@echo off\r\nkextest stress\r\n' > $(B)/iso/STRESS.BAT
	for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do printf '@echo off\r\nC:\\KEXTEST\\CHRVAR.EXE %s\r\n' $$n > $(B)/iso/CHRVAR$$n.BAT; done
	printf '@echo off\r\nC:\\KEXTEST\\KEXDBG.EXE -attach EXPLORER.EXE -log C:\\EXPLDBG.LOG\r\n' > $(B)/iso/EXPLDBG.BAT
	cp tests/chrome159_shm.bp $(B)/iso/KEXDBG.BP
	sed 's/$$/\r/' tests/MYPAL_USER.JS > $(B)/iso/USER.JS
	cp vxd_alias/kexalias.vxd $(B)/iso/KEXALIAS.VXD
	cp tests/TRACEON.REG tests/TRACEOFF.REG tests/PROFON.REG tests/PROFOFF.REG tests/BOOSTON.REG tests/BOOSTOFF.REG tests/CHRBLOFF.REG tests/GLKEEPOFF.REG tests/GLKEEPON.REG tests/GATEOFF.REG tests/GATEON.REG $(B)/iso/
	sed 's/$$/\r/' README_ISO.TXT > $(B)/iso/README.TXT
	[ -z "$(ISO_NOTES)" ] || sed 's/$$/\r/' $(ISO_NOTES) >> $(B)/iso/README.TXT   # optional extra test notes for a test CD
	if command -v xorriso >/dev/null; then xorriso -as mkisofs -J -r -V KEXNG -o $(B)/kexng.iso $(B)/iso; \
	else python3 ../tools/mkiso.py -V KEXNG -o $(B)/kexng.iso $(B)/iso; fi

clean:
	rm -rf $(B)

.PHONY: all check iso clean verify
.SECONDARY:

# Regenerate apisets.txt from the Win10 api-set forwarders (needs win10/win98 dumps from tools/re_scripts).
RE_OUT ?= $(HOME)/re_out
apisets: $(B)/kexnt.def
	python3 ../tools/re_scripts/gen_apisets.py --win10 $(RE_OUT)/win10_dump.json --win98 $(RE_OUT)/win98cd_dump.json \
	  --kex ../docs/kex_inventory.json --kexnt-def $(B)/kexnt.def --manual apisets_manual.txt \
	  -o apisets.txt --report ../docs/apisets_report.md
.PHONY: apisets

# KEXALIAS.VXD (helper VxD, ring 0) - needs Open Watcom (WATCOM=...); the built kexalias.vxd is kept in vxd_alias/
vxd:
	cd vxd_alias && PATH=$(WATCOM)/binl64:$$PATH INCLUDE=$(WATCOM)/h:$(WATCOM)/h/nt WATCOM=$(WATCOM) \
	  wcc386 -q -wx -s -zls -mf -DVXD32 -fpi87 -ei -oeatxhn -wcd=303 -5s -fp5 -fo=kexalias.obj kexalias.c && \
	  PATH=$(WATCOM)/binl64:$$PATH WATCOM=$(WATCOM) wlink op quiet @kexalias.lnk && \
	  (test -x fixlink.bin || gcc -O2 fixlink.c -o fixlink.bin) && ./fixlink.bin -vxd32 kexalias.vxd
.PHONY: vxd
