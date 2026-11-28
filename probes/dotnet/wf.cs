// wf.cs - Windows Workflow Foundation 3.0: sequential workflow with Code/While/IfElse/Delay activities run 50 times
// by WorkflowRuntime (ManualWorkflowSchedulerService and the default threaded scheduler). C:\T\WF.LOG
using System;
using System.Threading;
using System.Workflow.Activities;
using System.Workflow.ComponentModel;
using System.Workflow.Runtime;
using System.Workflow.Runtime.Hosting;

public class Flow : SequentialWorkflowActivity {
    public int Count, Hits;
    public Flow() {
        WhileActivity loop = new WhileActivity("loop");
        CodeCondition cond = new CodeCondition(); cond.Condition += delegate(object s, ConditionalEventArgs e) { e.Result = Count < 10; };
        loop.Condition = cond;
        CodeActivity inc = new CodeActivity("inc"); inc.ExecuteCode += delegate { Count++; };
        loop.Activities.Add(inc);
        IfElseActivity ife = new IfElseActivity("ife");
        IfElseBranchActivity yes = new IfElseBranchActivity("yes");
        CodeCondition c2 = new CodeCondition(); c2.Condition += delegate(object s, ConditionalEventArgs e) { e.Result = Count == 10; };
        yes.Condition = c2;
        CodeActivity hit = new CodeActivity("hit"); hit.ExecuteCode += delegate { Hits++; }; yes.Activities.Add(hit);
        ife.Activities.Add(yes); ife.Activities.Add(new IfElseBranchActivity("no"));
        DelayActivity delay = new DelayActivity("delay"); delay.TimeoutDuration = TimeSpan.FromMilliseconds(50);
        Activities.Add(loop); Activities.Add(ife); Activities.Add(delay);
    }
}

class P {
    static int Main() {
        T.Init("WF");
        T.Run("runtime default scheduler x50", delegate {
            using (WorkflowRuntime rt = new WorkflowRuntime()) {
                int done = 0, bad = 0; AutoResetEvent all = new AutoResetEvent(false);
                rt.WorkflowCompleted += delegate(object s, WorkflowCompletedEventArgs e) {
                    if ((int)e.OutputParameters["Count"] != 10 || (int)e.OutputParameters["Hits"] != 1) Interlocked.Increment(ref bad);
                    if (Interlocked.Increment(ref done) == 50) all.Set();
                };
                rt.WorkflowTerminated += delegate(object s, WorkflowTerminatedEventArgs e) { T.Log("terminated: " + e.Exception); Interlocked.Increment(ref bad); if (Interlocked.Increment(ref done) == 50) all.Set(); };
                rt.StartRuntime();
                for (int i = 0; i < 50; i++) rt.CreateWorkflow(typeof(Flow)).Start();
                T.Check(all.WaitOne(60000, false), "50 done, got " + done);
                T.Check(bad == 0, bad + " bad results");
            }
        });
        T.Run("runtime manual scheduler", delegate {
            using (WorkflowRuntime rt = new WorkflowRuntime()) {
                ManualWorkflowSchedulerService m = new ManualWorkflowSchedulerService(true); rt.AddService(m);
                bool ok = false; rt.WorkflowCompleted += delegate(object s, WorkflowCompletedEventArgs e) { ok = (int)e.OutputParameters["Count"] == 10; };
                rt.StartRuntime(); WorkflowInstance wi = rt.CreateWorkflow(typeof(Flow)); wi.Start();
                for (int i = 0; i < 100 && !ok; i++) { m.RunWorkflow(wi.InstanceId); Thread.Sleep(20); }
                T.Check(ok, "completed");
            }
        });
        return T.End();
    }
}
