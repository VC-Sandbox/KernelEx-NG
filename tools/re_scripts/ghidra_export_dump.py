# ghidra_export_dump.py - Ghidra headless post-script (Jython 2.7 and PyGhidra compatible).
# Dumps every function: name, address, calling convention, signature, stack purge,
# thunk target, export flag, plus imports, to JSON.
#
# analyzeHeadless C:\ghidra_proj KexRE -import C:\re\in\KERNEL32.DLL ^
#     -postScript ghidra_export_dump.py C:\re\out\KERNEL32.ghidra.json ^
#     -scriptPath C:\re\scripts -deleteProject
# @category KernelEx
import json

args = getScriptArgs()
out_path = args[0] if len(args) > 0 else (currentProgram.getName() + ".ghidra.json")
with_disasm = len(args) > 1 and args[1] == "--disasm"   # optional: first 64 instructions per export

prog = currentProgram
fm = prog.getFunctionManager()
st = prog.getSymbolTable()
listing = prog.getListing()

exports = set()
for addr in st.getExternalEntryPointIterator():
    exports.add(addr.getOffset())


def func_record(f):
    rec = {
        "name": f.getName(), "address": "0x%08x" % f.getEntryPoint().getOffset(),
        "calling_convention": f.getCallingConventionName(),
        "signature": f.getSignature().getPrototypeString(),
        "param_count": f.getParameterCount(), "stack_purge": f.getStackPurgeSize(),
        "body_size": f.getBody().getNumAddresses(), "is_thunk": f.isThunk(),
        "is_export": f.getEntryPoint().getOffset() in exports, "thunk_target": None,
    }
    if f.isThunk():
        t = f.getThunkedFunction(True)
        if t is not None:
            rec["thunk_target"] = {"name": t.getName(), "address": str(t.getEntryPoint()),
                                   "external": t.isExternal()}
            loc = t.getExternalLocation() if t.isExternal() else None
            if loc is not None:
                rec["thunk_target"]["library"] = loc.getLibraryName()
    if with_disasm and rec["is_export"]:
        ins, it = [], listing.getInstructions(f.getEntryPoint(), True)
        while it.hasNext() and len(ins) < 64:
            i = it.next()
            ins.append("%s  %s" % (i.getAddress(), i))
        rec["disasm"] = ins
    return rec


funcs = [func_record(f) for f in fm.getFunctions(True)]
imports = []
for f in fm.getExternalFunctions():
    loc = f.getExternalLocation()
    imports.append({"name": f.getName(), "library": loc.getLibraryName() if loc else None})

doc = {"tool": "ghidra_export_dump", "version": 1, "program": prog.getName(),
       "image_base": str(prog.getImageBase()), "language": str(prog.getLanguageID()),
       "functions": funcs, "imports": imports,
       "summary": {"functions": len(funcs), "exports": len(exports), "imports": len(imports)}}
fh = open(out_path, "w")
fh.write(json.dumps(doc, indent=1))
fh.close()
print("ghidra_export_dump: wrote %s (%d functions)" % (out_path, len(funcs)))
