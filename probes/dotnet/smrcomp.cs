// smrcomp.cs - probe: run each install component of WCF's ServiceModelReg.exe (classes deriving from a type whose name
// ends in "InstallComponent") through reflection and log the full exception of the ones that fail; ServiceModelReg
// itself prints only "Error: <message>". C:\T\SMRCOMP.LOG
using System;
using System.Reflection;

class P {
    static int Main() {
        T.Init("SMRCOMP");
        Assembly a = Assembly.LoadFrom(@"C:\WINDOWS\Microsoft.NET\Framework\v3.0\Windows Communication Foundation\ServiceModelReg.exe");
        foreach (Type t in a.GetTypes()) {
            bool comp = false; for (Type b = t.BaseType; b != null; b = b.BaseType) if (b.Name.EndsWith("InstallComponent")) comp = true;
            if (!comp || t.IsAbstract) continue;
            Type tt = t;
            T.Run(t.FullName, delegate {
                foreach (ConstructorInfo ci in tt.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)) {
                    string sig = ""; foreach (ParameterInfo pi in ci.GetParameters()) sig += pi.ParameterType.Name + " "; T.Log("ctor (" + sig + ")"); }
                object o = null;
                foreach (ConstructorInfo ci in tt.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)) {
                    ParameterInfo[] cp = ci.GetParameters();
                    if (cp.Length == 1 && cp[0].ParameterType.Name.EndsWith("ConfigurationLoader")) {
                        Type lt = cp[0].ParameterType; object ld = null;
                        foreach (ConstructorInfo lc in lt.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)) {
                            string sig = ""; foreach (ParameterInfo pi in lc.GetParameters()) sig += pi.ParameterType.Name + " "; T.Log(lt.Name + " ctor (" + sig + ")");
                            if (lc.GetParameters().Length == 0 && !lt.IsAbstract) ld = lc.Invoke(null);
                        }
                        if (ld == null) foreach (Type ct in a.GetTypes())
                            if (!ct.IsAbstract && lt.IsAssignableFrom(ct) && ct.GetConstructor(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null, Type.EmptyTypes, null) != null) {
                                T.Log("loader " + ct.Name); ld = Activator.CreateInstance(ct, true); break; }
                        if (ld == null) foreach (MethodInfo f in lt.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
                            if (f.ReturnType == lt && f.GetParameters().Length == 0) { T.Log("factory " + f.Name); ld = f.Invoke(null, null); break; }
                        o = ci.Invoke(new object[] { ld });
                    }
                }
                if (o == null) o = Activator.CreateInstance(tt, true);
                foreach (MethodInfo m in tt.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)) {
                    if (m.Name != "Install") continue;
                    ParameterInfo[] ps = m.GetParameters(); object[] args = new object[ps.Length];
                    for (int i = 0; i < ps.Length; i++) { args[i] = ps[i].ParameterType.IsValueType ? Activator.CreateInstance(ps[i].ParameterType) : null; T.Log("arg " + ps[i].ParameterType.Name); }
                    m.Invoke(o, args);
                    return;
                }
                T.Log("no Install method");
            });
        }
        return T.End();
    }
}
