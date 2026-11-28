// wcfhost.cs - probe: open a WCF net.tcp host (as wcf.cs does) and keep it open 60 s, so `netstat -an` can show what
// it listens on. C:\T\WCFHOST.LOG
using System;
using System.ServiceModel;
using System.Threading;
[ServiceContract] public interface IPing { [OperationContract] int Ping(int x); }
public class Pinger : IPing { public int Ping(int x) { return x + 1; } }
class P {
    static int Main() {
        T.Init("WCFHOST");
        T.Run("open host and wait 60 s", delegate {
            ServiceHost h = new ServiceHost(typeof(Pinger));
            h.AddServiceEndpoint(typeof(IPing), new NetTcpBinding(SecurityMode.None), "net.tcp://localhost:8731/ping"); h.Open();
            foreach (System.ServiceModel.Dispatcher.ChannelDispatcherBase d in h.ChannelDispatchers) T.Log("listener " + d.Listener.Uri + " state " + d.State);
            Thread.Sleep(60000); h.Close();
        });
        return T.End();
    }
}
