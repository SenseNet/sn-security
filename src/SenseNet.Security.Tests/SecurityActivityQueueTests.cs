using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Configuration;
using SenseNet.Diagnostics;
using SenseNet.Security.Tests.TestPortal;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.EntityFrameworkCore;
using SenseNet.Security.Data;

namespace SenseNet.Security.Tests;

[TestClass]
public class SecurityActivityQueueTests : TestBase
{
    private Context _context;
    public TestContext TestContext { get; set; }

    [TestInitialize]
    public void StartTest()
    {
        _StartTest(TestContext);
    }
    [TestCleanup]
    public void FinishTest()
    {
        try
        {
            CheckIntegrity(TestContext.TestName, _context.Security);
        }
        finally
        {
            _FinishTest(TestContext);
        }
    }

    [TestMethod]
    public async Task SAQ_1()
    {
        //---- Ensure test data
        var entities = SystemStartTests.CreateTestEntities();
        var groups = SystemStartTests.CreateTestGroups();
        //var memberships = Tools.CreateInMemoryMembershipTable("G1:U1,U2|G2:U3,U4|G3:U1,U3|G4:U4|G5:U5");
        var memberships = Tools.CreateInMemoryMembershipTable(groups);
        var aces = SystemStartTests.CreateTestAces();
        var storage = new DatabaseStorage
        {
            Aces = aces,
            Memberships = memberships,
            Entities = entities,
            Messages = new List<Tuple<int, DateTime, byte[]>>()
        };

        var securitySystem = Context.StartTheSystem(
            new MemoryDataProvider(storage), DiTools.CreateDefaultMessageProvider(), legacy: false);

        // ACTION
        var idE53 = GetId("E53");
        var idE54 = GetId("E54");
        var idU1 = GetId("U1");
        _context = new Context(TestUser.User1, securitySystem);
        _context.Security.CreateSecurityEntity(idE54, idE53, idU1);

        //ASSERT
        await Task.Delay(100);
        _context.Security.SecuritySystem.Shutdown();
        var x = _context.Security.GetEffectiveEntries(idE54);
        Assert.IsTrue(securitySystem.Cache.Entities.TryGetValue(idE54, out var entity54));
        Assert.AreEqual(idE53, entity54.Parent.Id);
        Assert.AreEqual(idU1, entity54.OwnerId);
    }
}