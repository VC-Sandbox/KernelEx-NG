#!/bin/sh
# gen_apiset_deps.sh <apiset> <builddir> <dlltool>
# Creates <builddir>/<apiset>.deps.c plus one tiny import library per forward-target DLL
# (from the "#dep" lines of apisets.txt) and prints the libraries to link.
set -e
s=$1; b=$2; dlltool=$3
c=$b/$s.deps.c
rm -f $b/$s.dep_*
echo "/* generated: static imports that force the 9x loader to map forward targets */" > $c
libs=""
cat ${APISET_TABLES:-apisets.txt} | grep "^#dep $s " | while read _ _ dll fn; do
    printf 'LIBRARY %s.dll\nEXPORTS\n    KexDep_%s == %s\n' "$dll" "$dll" "$fn" > $b/$s.dep_$dll.def
    $dlltool -d $b/$s.dep_$dll.def -l $b/$s.dep_$dll.a
    printf '__declspec(dllimport) void KexDep_%s(void);\n' "$dll" >> $c
done
echo "void *const kex_apiset_deps[] = {" >> $c
cat ${APISET_TABLES:-apisets.txt} | grep "^#dep $s " | while read _ _ dll fn; do printf '    (void *)KexDep_%s,\n' "$dll" >> $c; done
echo "    0 };" >> $c
for l in $b/$s.dep_*.a; do [ -f "$l" ] && libs="$libs $l"; done
echo $libs
