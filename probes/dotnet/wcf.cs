// wcf.cs - Windows Communication Foundation 3.0/3.5: self-hosted service over NetTcpBinding (no security) on loopback,
// 500 calls from 10 threads, a data contract, a fault, a duplex-free one-way call; DataContractSerializer and
// DataContractJsonSerializer (3.5) round trips. C:\T\WCF.LOG
using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.ServiceModel;
using System.Text;
using System.Threading;

[DataContract] public class Item { [DataMember] public int Id; [DataMember] public string Name; }

[ServiceContract] public interface ICalc {
    [OperationContract] int Add(int a, int b);
    [OperationContract] Item Echo(Item i);
    [OperationContract] [FaultContract(typeof(string))] void Fail();
    [OperationContract(IsOneWay = true)] void Ping();
}
public class Calc : ICalc {
    public static int Pings;
    public int Add(int a, int b) { return a + b; }
    public Item Echo(Item i) { i.Name = i.Name + "!"; return i; }
    public void Fail() { throw new FaultException<string>("boom", "boom"); }
    public void Ping() { Interlocked.Increment(ref Pings); }
}

class P {
    static int Main() {
        T.Init("WCF");
        T.Run("DataContractSerializer", delegate {
            MemoryStream m = new MemoryStream(); Item i = new Item(); i.Id = 3; i.Name = "a";
            new DataContractSerializer(typeof(Item)).WriteObject(m, i); m.Position = 0;
            T.Check(((Item)new DataContractSerializer(typeof(Item)).ReadObject(m)).Name == "a", "roundtrip");
        });
        T.Run("DataContractJsonSerializer (3.5)", delegate {
            MemoryStream m = new MemoryStream(); Item i = new Item(); i.Id = 4; i.Name = "j";
            new DataContractJsonSerializer(typeof(Item)).WriteObject(m, i);
            string s = Encoding.UTF8.GetString(m.ToArray()); T.Log(s); T.Check(s.Contains("\"Id\":4"), "json");
        });
        ServiceHost h = null; string addr = "net.tcp://localhost:8731/calc";
        T.Run("ServiceHost open (net.tcp, no security)", delegate {
            h = new ServiceHost(typeof(Calc));
            h.AddServiceEndpoint(typeof(ICalc), new NetTcpBinding(SecurityMode.None), addr); h.Open();
        });
        T.Run("client: 500 calls on 10 threads", delegate {
            ChannelFactory<ICalc> f = new ChannelFactory<ICalc>(new NetTcpBinding(SecurityMode.None), addr);
            int bad = 0; Thread[] th = new Thread[10];
            for (int t = 0; t < th.Length; t++) {
                th[t] = new Thread(delegate() {
                    ICalc c = f.CreateChannel();
                    for (int k = 0; k < 50; k++) if (c.Add(k, 1) != k + 1) Interlocked.Increment(ref bad);
                    ((IClientChannel)c).Close();
                }); th[t].Start();
            }
            foreach (Thread t in th) t.Join(); f.Close(); T.Check(bad == 0, bad + " wrong");
        });
        T.Run("data contract echo, fault, one-way", delegate {
            ChannelFactory<ICalc> f = new ChannelFactory<ICalc>(new NetTcpBinding(SecurityMode.None), addr); ICalc c = f.CreateChannel();
            Item i = new Item(); i.Id = 1; i.Name = "x"; T.Check(c.Echo(i).Name == "x!", "echo");
            try { c.Fail(); throw new Exception("no fault"); } catch (FaultException<string> e) { T.Check(e.Detail == "boom", "fault detail"); }
            c.Ping(); c.Ping(); Thread.Sleep(500); T.Check(Calc.Pings == 2, "pings " + Calc.Pings);
            ((IClientChannel)c).Close(); f.Close();
        });
        T.Run("ServiceHost close", delegate { if (h != null) h.Close(); });
        return T.End();
    }
}
