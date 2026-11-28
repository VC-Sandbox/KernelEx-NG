// iishelper.cs - probe: run the static constructor of System.ServiceModel.Install.IisHelper from WCF's
// ServiceModelReg.exe and log the full exception (ServiceModelReg itself prints only the outer message). C:\T\IIS.LOG
using System;
using System.Reflection;
using System.Runtime.CompilerServices;

class P {
    static int Main() {
        T.Init("IIS");
        T.Run("IisHelper cctor", delegate {
            Assembly a = Assembly.LoadFrom(@"C:\WINDOWS\Microsoft.NET\Framework\v3.0\Windows Communication Foundation\ServiceModelReg.exe");
            Type t = a.GetType("System.ServiceModel.Install.IisHelper", true);
            RuntimeHelpers.RunClassConstructor(t.TypeHandle);
        });
        return T.End();
    }
}
