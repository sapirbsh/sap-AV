using SapAV.Engine.Persistence.Remediation;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// D5, opt-in only (elevated and <c>SAPAV_TEST_ALLOW_HKLM=1</c>, since it registers a machine task): the real Task Scheduler
/// control on a throwaway task it creates itself (no trigger, so it never runs) under <c>\sap-AV-tests\</c>, removed afterwards.
/// </summary>
public sealed class RealTaskSchedulerTests
{
    private const string Folder = @"\sap-AV-tests";

    [RequiresFact(Requires.RunningElevated, Requires.HklmWritesAllowed)]
    public void ThrowawayTask_DisableAndEnable_ThroughTheTaskSchedulerApi()
    {
        string name = "d5-" + Guid.NewGuid().ToString("N");
        string path = $@"{Folder}\{name}";
        dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
        service.Connect();
        dynamic root = service.GetFolder(@"\");
        dynamic folder;
        try
        {
            folder = root.GetFolder(Folder);
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            folder = root.CreateFolder(Folder);
        }

        const string xml = """
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
              <Settings><Enabled>true</Enabled></Settings>
              <Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>/c exit 0</Arguments></Exec></Actions>
            </Task>
            """;
        folder.RegisterTask(name, xml, 6 /* TASK_CREATE_OR_UPDATE */, null, null, 5 /* TASK_LOGON_SERVICE_ACCOUNT */);
        try
        {
            var control = ComTaskSchedulerControl.Instance;
            Assert.Equal(TaskControlStatus.Ok, control.Get(path, out var before));
            Assert.True(before!.Enabled);

            Assert.Equal(TaskControlStatus.Ok, control.SetEnabled(path, false));
            Assert.Equal(TaskControlStatus.Ok, control.Get(path, out var disabled));
            Assert.False(disabled!.Enabled);

            Assert.Equal(TaskControlStatus.Ok, control.SetEnabled(path, true));
            Assert.Equal(TaskControlStatus.Ok, control.Get(path, out var enabled));
            Assert.True(enabled!.Enabled);
            Assert.Equal(TaskControlStatus.NotFound, control.Get(path + "-missing", out _));
        }
        finally
        {
            folder.DeleteTask(name, 0);
            try
            {
                root.DeleteFolder(Folder, 0); // only when empty
            }
            catch (System.Runtime.InteropServices.COMException)
            {
            }
        }
    }
}
