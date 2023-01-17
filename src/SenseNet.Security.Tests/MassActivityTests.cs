using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Diagnostics;
using SenseNet.Security.Messaging.SecurityMessages;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests;

[TestClass]
public class MassActivityTests : TestBase
{
    public TestContext TestContext { get; set; }

    [TestInitialize]
    public void StartTest()
    {
        _StartTest(TestContext);
        SnTrace.EnableAll();
    }

    [TestMethod]
    public void MassActivity_1()
    {
        var messageQueue = new Queue<byte[]>();
        var theSystem = MessagingTests2.CreateSecuritySystem("theSystem", messageQueue, false);

        var count = 20;

        var tasks = Enumerable.Range(0, count)
            //.Select(i => Task.Run(() => TaskCode(1000 + i, theSystem)))
            .Select(i => Task.Factory.StartNew(() => TaskCode(1000 + i, theSystem), TaskCreationOptions.LongRunning))
            .ToArray();

        Task.WaitAll(tasks);

        Task.Delay(2_000).GetAwaiter().GetResult();
    }

    void TaskCode(int id, SecuritySystem theSystem)
    {
        using var op = SnTrace.Test.StartOperation("TaskCode " + id);
        var ctx = new SecurityContext(TestUser.User1, theSystem);
        ctx.CreateSecurityEntity(id, 2, 1);
        op.Successful = true;
    }
}