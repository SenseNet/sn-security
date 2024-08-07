﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Diagnostics;
using SenseNet.Security.Tests.TestPortal;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using SenseNet.Security.Data;
using System.Linq;
using SenseNet.Diagnostics.Analysis;
using System.Diagnostics;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Tests;

[TestClass]
public class SecurityActivityQueueTests : TestBase
{
    private Context _context;

    [TestMethod]
    public async Task SAQ_CreateEntity_One()
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

        var securitySystem = Context.StartTheSystem(new MemoryDataProvider(storage), DiTools.CreateDefaultMessageProvider());

        // ACTION
        var idE53 = GetId("E53");
        var idE54 = GetId("E54");
        var idU1 = GetId("U1");
        _context = new Context(TestUser.User1, securitySystem);
        await _context.Security.CreateSecurityEntityAsync(idE54, idE53, idU1, CancellationToken.None)
            .ConfigureAwait(false);

        //ASSERT
        await Task.Delay(100);
        _context.Security.SecuritySystem.Shutdown();
        Assert.IsTrue(securitySystem.Cache.Entities.TryGetValue(idE54, out var entity54));
        Assert.AreEqual(idE53, entity54.Parent.Id);
        Assert.AreEqual(idU1, entity54.OwnerId);

        var trace = _testTracer.Lines;
        var msg = CheckTrace(trace, 1);
        Assert.AreEqual(null, msg);
    }
    [TestMethod]
    public async Task SAQ_CreateEntity_Duplications()
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

        var securitySystem = Context.StartTheSystem(new MemoryDataProvider(storage), DiTools.CreateDefaultMessageProvider());

        var idE53 = GetId("E53");
        var idE54 = GetId("E54");
        var idE55 = GetId("E55");
        var idE56 = GetId("E56");
        var idU1 = GetId("U1");
        _context = new Context(TestUser.User1, securitySystem);
        var cancel = CancellationToken.None;

        // Create 2 activities (FromReceiver = true avoids duplicated saves).
        var activity1 = new CreateSecurityEntityActivity(idE54, idE53, idU1) {FromReceiver = true};
        await securitySystem.DataHandler.SaveActivityAsync(activity1, cancel).ConfigureAwait(false);
        var activity2 = new CreateSecurityEntityActivity(idE55, idE54, idU1) { FromReceiver = true };
        await securitySystem.DataHandler.SaveActivityAsync(activity2, cancel).ConfigureAwait(false);
        // Duplicate both activities.
        var loaded = (await securitySystem.DataHandler
            .LoadSecurityActivitiesAsync(activity1.Id, activity2.Id, 2, false, cancel)
            .ConfigureAwait(false)).ToArray();

        // ACTION execute in wrong order
        var tasks = new[]
        {
            loaded[1].ExecuteAsync(_context.Security, cancel), // copied activity2
            activity2.ExecuteAsync(_context.Security, cancel), // waits for activity1 (E54 creation)
            loaded[0].ExecuteAsync(_context.Security, cancel), // copied activity1
            activity1.ExecuteAsync(_context.Security, cancel), // execute all
        };
        await Task.WhenAll(tasks);

        //ASSERT
        await Task.Delay(100);
        _context.Security.SecuritySystem.Shutdown();

        Assert.IsTrue(securitySystem.Cache.Entities.TryGetValue(idE54, out var entity54));
        Assert.AreEqual(idE53, entity54.Parent.Id);
        Assert.AreEqual(idU1, entity54.OwnerId);
        Assert.IsTrue(securitySystem.Cache.Entities.TryGetValue(idE55, out var entity55));
        Assert.AreEqual(idE54, entity55.Parent.Id);
        Assert.AreEqual(idU1, entity55.OwnerId);

        var trace = _testTracer.Lines;
        var msg = CheckTrace(trace, 2);
        Assert.AreEqual(null, msg);
    }
    [TestMethod]
    public async Task SAQ_CreateEntity_Duplications_Forced_SameObject()
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

        var securitySystem = Context.StartTheSystem(new MemoryDataProvider(storage), DiTools.CreateDefaultMessageProvider());

        var idU1 = GetId("U1");
        var idG1 = GetId("G1");
        _context = new Context(TestUser.User1, securitySystem);
        var cancel = CancellationToken.None;

        // Create an activity that depends from itself (FromReceiver = true avoids duplicated saves).
        var activity1 = new AddUserToSecurityGroupsActivity(idU1, new[] {idG1})
        {
            Id = 1,
            Context = _context.Security,
            FromReceiver = true,
        };

        // ACTION
        // force add to currently executed list
        var saq = securitySystem.SecurityActivityQueue;
        var saqAcc = new ObjectAccessor(saq);
        var executionList = (List<SecurityActivity>)saqAcc.GetField("_executingList");
        executionList.Add(activity1);
        // try to make infinite loop: "Make dependency: #SA1-1 depends from SA1-1."
        saq.ExecuteActivityAsync(activity1, cancel);

        //ASSERT
        await Task.Delay(1000);
        //_context.Security.SecuritySystem.Shutdown();

        var trace = _testTracer.Lines;
        Assert.IsTrue(trace.Count <= 70, $"Trace has {trace.Count} lines that greater than the expected 70.");
        var msg = CheckTrace(trace, 1);
        Assert.AreEqual(null, msg);
    }
    [TestMethod]
    public async Task SAQ_CreateEntity_Duplications_Forced_SameId()
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

        var securitySystem = Context.StartTheSystem(new MemoryDataProvider(storage), DiTools.CreateDefaultMessageProvider());

        var idU1 = GetId("U1");
        var idG1 = GetId("G1");
        _context = new Context(TestUser.User1, securitySystem);
        var cancel = CancellationToken.None;

        // Create an activity that depends from itself (FromReceiver = true avoids duplicated saves).
        var activity1 = new AddUserToSecurityGroupsActivity(idU1, new[] { idG1 })
        {
            Id = 1,
            Context = _context.Security,
            FromReceiver = true,
        };
        var activity2 = new AddUserToSecurityGroupsActivity(idU1, new[] { idG1 })
        {
            Id = 1,
            Context = _context.Security,
            FromReceiver = true,
        };

        // ACTION
        // force add to currently executed list
        var saq = securitySystem.SecurityActivityQueue;
        var saqAcc = new ObjectAccessor(saq);
        var executionList = (List<SecurityActivity>)saqAcc.GetField("_executingList");
        executionList.Add(activity1);
        // try to make infinite loop: "Make dependency: #SA1-1 depends from SA1-1."
        saq.ExecuteActivityAsync(activity2, cancel);

        //ASSERT
        await Task.Delay(1000);
        _context.Security.SecuritySystem.Shutdown();

        var trace = _testTracer.Lines;
        Assert.IsTrue(trace.Count <= 70, $"Trace has {trace.Count} lines that greater than the expected 70.");
        // The "CheckTrace(trace, 1)" is skipped: #SA1-1 is "not in the right order"
        // because the trace is incomplete due to hacked start.
        // Rather check the trace for the following lines.
        var allEntries = trace.Select(Entry.Parse).ToArray();
        Assert.IsTrue(allEntries.Any(e => e.Message == $"SA: ExecuteInternal #SA{activity1.Key}"));
        Assert.IsTrue(allEntries.Any(e => e.Message == $"SAQT: State after finishing SA1: 1()"));
        Assert.IsTrue(allEntries.Any(e => e.Message == $"SAQT: execution ignored (attachment): #SA{activity2.Key}"));
    }
    [TestMethod]
    public async Task SAQ_CreateEntity_ArrivalInWrongDependencyOrder()
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

        var securitySystem = Context.StartTheSystem(new MemoryDataProvider(storage), DiTools.CreateDefaultMessageProvider());

        var idE53 = GetId("E53");
        var idE54 = GetId("E54");
        var idE55 = GetId("E55");
        var idE56 = GetId("E56");
        var idU1 = GetId("U1");
        _context = new Context(TestUser.User1, securitySystem);
        var cancel = CancellationToken.None;

        // Create 3 activities (FromReceiver = true avoids duplicated saves).
        var activity1 = new CreateSecurityEntityActivity(idE54, idE53, idU1) { FromReceiver = true };
        await securitySystem.DataHandler.SaveActivityAsync(activity1, cancel).ConfigureAwait(false);
        var activity2 = new CreateSecurityEntityActivity(idE55, idE54, idU1) { FromReceiver = true };
        await securitySystem.DataHandler.SaveActivityAsync(activity2, cancel).ConfigureAwait(false);
        var activity3 = new CreateSecurityEntityActivity(idE56, idE54, idU1) { FromReceiver = true };
        await securitySystem.DataHandler.SaveActivityAsync(activity3, cancel).ConfigureAwait(false);

        // ACTION execute in wrong order
        var tasks = new[]
        {
            activity2.ExecuteAsync(_context.Security, cancel), // waits for activity1 (E54 creation)
            activity3.ExecuteAsync(_context.Security, cancel), // waits for activity1 (E54 creation)
            activity1.ExecuteAsync(_context.Security, cancel), // execute all
        };
        await Task.WhenAll(tasks);

        //ASSERT
        await Task.Delay(100);
        _context.Security.SecuritySystem.Shutdown();

        Assert.IsTrue(securitySystem.Cache.Entities.TryGetValue(idE54, out var entity54));
        Assert.AreEqual(idE53, entity54.Parent.Id);
        Assert.AreEqual(idU1, entity54.OwnerId);
        Assert.IsTrue(securitySystem.Cache.Entities.TryGetValue(idE55, out var entity55));
        Assert.AreEqual(idE54, entity55.Parent.Id);
        Assert.AreEqual(idU1, entity55.OwnerId);
        Assert.IsTrue(securitySystem.Cache.Entities.TryGetValue(idE56, out var entity56));
        Assert.AreEqual(idE54, entity56.Parent.Id);
        Assert.AreEqual(idU1, entity56.OwnerId);

        var trace = _testTracer.Lines;
        var msg = CheckTrace(trace, 3);
        Assert.AreEqual(null, msg);
    }

    #region Infrastructure & Tools

    public TestContext TestContext { get; set; }

    [TestInitialize]
    public void StartTest()
    {
        _StartTest(TestContext);

        SnTrace.SecurityQueue.Enabled = true;

        var tracers = SnTrace.SnTracers;
        _testTracer = (TestTracer)tracers.FirstOrDefault(t => t is TestTracer)!;
        if (_testTracer == null)
        {
            _testTracer = new TestTracer();
            tracers.Add(_testTracer);
        }
        else
        {
            _testTracer.Clear();
        }
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


    private class TestTracer : ISnTracer
    {
        private readonly object _lock = new();
        public List<string> Lines { get; } = new();
        public void Write(string line) { lock (_lock) Lines.Add(line); }
        public void Flush() { /* do nothing */ }
        public void Clear() { Lines.Clear(); }
    }
    private TestTracer _testTracer;

    private string CheckTrace(List<string> trace, int count)
    {
        var t0 = Entry.Parse(trace.First()).Time;

        var allEvents = new Dictionary<string, ActivityEvents>();
        var allEntries = trace.Select(Entry.Parse).ToArray();
        foreach (var entry in allEntries)
        {
            // SAQT: execution ignored immediately: A1-1
            // SAQT: execution finished: A1-1
            // SAQT: execution ignored (attachment): A1-1

            if (ParseLine(allEvents, entry, "App: Business executes ", "Start", out var item))
                item.BusinessStart = entry.LineId;
            else if (ParseLine(allEvents, entry, "App: Business executes ", "End", out item))
                item.BusinessEnd = entry.LineId;
            else if (ParseLine(allEvents, entry, "DataHandler: SaveActivity ", "Start", out item))
                item.SaveStart = entry.LineId;
            else if (ParseLine(allEvents, entry, "DataHandler: SaveActivity ", "End", out item))
                item.SaveEnd = entry.LineId;
            else if (ParseLine(allEvents, entry, "SAQ: Arrive from receiver ", null, out item))
            { item.Arrival = entry.LineId; item.FromDbOrReceiver = true; }
            else if (ParseLine(allEvents, entry, "SAQ: Arrive from database ", null, out item))
            { item.Arrival = entry.LineId; item.FromDbOrReceiver = true; }
            else if (ParseLine(allEvents, entry, "SAQ: Arrive ", null, out item))
                item.Arrival = entry.LineId;
            else if (ParseLine(allEvents, entry, "SAQT: start execution: ", null, out item))
                item.Execution = entry.LineId;
            else if (ParseLine(allEvents, entry, "SA: ExecuteInternal ", "Start", out item))
                item.InternalExecutionStart = entry.LineId;
            else if (ParseLine(allEvents, entry, "SA: ExecuteInternal ", "End", out item))
                item.InternalExecutionEnd = entry.LineId;
            else if (ParseLine(allEvents, entry, "SAQT: execution finished: ", null, out item))
                item.Released = entry.LineId;
            else if (ParseLine(allEvents, entry, "SAQT: execution ignored immediately: ", null, out item))
            { item.ExecutionIgnored = true; item.Released = entry.LineId; }
            else if (ParseLine(allEvents, entry, "SAQT: execution ignored (attachment): ", null, out item))
            { item.ExecutionIgnored = true; item.Released = entry.LineId; }
        }

        // fix activity id by objectid when the id is null (not saved yet).
        var notSavedEvents = allEvents.Values.Where(x => x.Id == 0).ToArray();
        foreach (var notSaved in notSavedEvents)
        {
            var saved = allEvents.Values.First(x => x.Id != 0 && x.ObjectId == notSaved.ObjectId);
            saved.BusinessStart = notSaved.BusinessStart;
            saved.BusinessEnd = notSaved.BusinessEnd;
            saved.SaveStart = notSaved.SaveStart;
            saved.SaveEnd = notSaved.SaveEnd;
            allEvents.Remove(notSaved.Key);
        }

        foreach (var entry in allEntries)
        {
            if (ParseLine(allEvents, entry, "SA: Make dependency: ", null, out var item))
                item.DependsFrom.Add(ParseDependsFrom(allEvents, entry.Message));
        }

        var grouped = new Dictionary<int, Dictionary<int, ActivityEvents>>();
        foreach (var events in allEvents.Values)
        {
            if (!grouped.TryGetValue(events.Id, out var outer))
            {
                outer = new Dictionary<int, ActivityEvents>();
                grouped.Add(events.Id, outer);
            }
            outer.Add(events.ObjectId, events);
        }

        if (grouped.Count != count)
            return $"events.Count = {grouped.Count}, expected: {count}";

        foreach (var events in allEvents)
        {
            if (!events.Value.IsRightOrder())
                return $"events[{events.Key}] is not in the right order: {events.Value.TraceTimes()}";
        }

        foreach (var events in grouped.Values)
        {
            var executedCount = events.Values.Count(x => !x.ExecutionIgnored);
            var ignoredCount = events.Values.Count(x => x.ExecutionIgnored);
            var savedCount = events.Values.Count(x => x.Saved);
            if (executedCount > 1)
                return $"A{events.First().Value.Id} is executed more times.";
            if (savedCount > 1)
                return $"A{events.First().Value.Id} is saved more times.";

            if (ignoredCount > 0)
            {
                // The BusinessEnd of all ignored items should greater BusinessEnd of executed item
                //     otherwise send message: "released earlier."
                var executed = events.Values
                    .First(x => !x.ExecutionIgnored);
                var ignored = events.Values
                    .Where(x => x.ExecutionIgnored)
                    .ToArray();
                foreach (var item in ignored)
                    if (item.Released <= executed.Released)
                        return $"A{item.Id} is executed too early.";
            }
        }



        var allExecuted = allEvents.Values
            .Where(x => !x.ExecutionIgnored)
            .OrderBy(x => x.Id)
            .ToArray();
        for (var i = 0; i < allExecuted.Length; i++)
        {
            if (allExecuted[i].DependsFrom.Count > 0)
            {
                foreach (var itemBefore in allExecuted[i].DependsFrom)
                {
                    if (allExecuted[i].InternalExecutionStart <= itemBefore.InternalExecutionEnd)
                        return $"The pending item A{allExecuted[i].Id} was started earlier " +
                               $"than A{itemBefore.Id} would have been completed.";
                }
                continue;
            }

            if (i < allExecuted.Length - 1)
                if (allExecuted[i].Execution >= allExecuted[i + 1].Execution)
                    return $"execTimes[A{allExecuted[i].Id}] and execTimes[A{allExecuted[i + 1].Id}] are not in the right order.";
        }

        //var businessEndIdsOrderedByTime = allEvents.Values
        //    .Where(x => !x.ExecutionIgnored)
        //    .OrderBy(x => x.BusinessEnd)
        //    .Select(x => x.Id)
        //    .ToArray();
        //for (var i = 0; i < businessEndIdsOrderedByTime.Length - 1; i++)
        //{
        //    if (businessEndIdsOrderedByTime[i] > businessEndIdsOrderedByTime[i + 1])
        //        return $"businessEndIdsOrderedByTime[{i}] and businessEndIdsOrderedByTime[{i + 1}] are not in the right order.";
        //}

        return null;
    }
    private char[] _trimChars = "#SA".ToCharArray();
    private ActivityEvents ParseDependsFrom(Dictionary<string, ActivityEvents> allEvents, string msg)
    {
        // SA: Make dependency: #SA4-5 depends from SA3-6.
        var p = msg.IndexOf("depends from ", StringComparison.Ordinal);
        var key = "#SA" + msg.Substring(p + 13).TrimStart(_trimChars).TrimEnd('.');
        return allEvents[key];
    }

    private bool ParseLine(Dictionary<string, ActivityEvents> events, Entry entry, string msg, string status, out ActivityEvents item)
    {
        if (entry.Message.StartsWith(msg) && (status == null || status == entry.Status))
        {
            var id = ParseItemId(entry.Message, msg.Length);
            item = EnsureItem(events, id);
            return true;
        }
        item = null;
        return false;
    }
    private string ParseItemId(string msg, int index)
    {
        var src = msg.Substring(index);
        var p = src.IndexOf(" ", StringComparison.Ordinal);
        if (p > 0)
            src = src.Substring(0, p);
        return src;
    }
    private ActivityEvents EnsureItem(Dictionary<string, ActivityEvents> items, string key)
    {
        if (items.TryGetValue(key, out var item))
            return item;

        var ids = key.Trim(_trimChars).Split('-').Select(int.Parse).ToArray();
        item = new ActivityEvents { Key = key, Id = ids[0], ObjectId = ids[1] };
        items.Add(key, item);
        return item;
    }

    [DebuggerDisplay("{Key}: ignored: {ExecutionIgnored}")]
    private class ActivityEvents
    {
        public int Id;
        public int ObjectId;
        public string Key;
        public bool FromDbOrReceiver;                     // 
        public int BusinessStart;                    // Start  App: Business executes #SA1
        public int SaveStart;                        // Start  DataHandler: SaveActivity #SA1
        public int SaveEnd;                          // End    DataHandler: SaveActivity #SA1
        public int Arrival;                          //        SAQ: Arrive #SA1
        public int Execution;                        //        SAQT: start execution: #SA1
        public int InternalExecutionStart;           // Start  SA: ExecuteInternal #SA1
        public int InternalExecutionEnd;             // End    SA: ExecuteInternal #SA1
        public int Released;                         //        SAQT: execution ignored immediately: #SA1-1
                                                          //        SAQT: execution finished: #SA1-1
                                                          //        SAQT: execution ignored (attachment): #SA1-1
        public int BusinessEnd;                      // End    App: Business executes #SA1
        public bool ExecutionIgnored;                     //        SAQT: execution ignored #SA3-1
        public List<ActivityEvents> DependsFrom = new();  //        SA: Make dependency: #SA4-5 depends from SA3-6.

        public bool Saved => SaveStart != 0;

        public bool IsRightOrder()
        {
            if (FromDbOrReceiver && ExecutionIgnored)
                return SaveStart == 0 &&
                       SaveEnd == 0 &&
                       BusinessStart == 0 &&
                       Arrival > 0 &&
                       Execution == 0 &&
                       InternalExecutionStart == 0 &&
                       InternalExecutionEnd == 0 &&
                       Released >= Arrival &&
                       BusinessEnd == 0;

            if (FromDbOrReceiver && !ExecutionIgnored)
                return SaveStart == 0 &&
                       SaveEnd == 0 &&
                       BusinessStart == 0 &&
                       Arrival > 0 &&
                       Execution >= Arrival &&
                       InternalExecutionStart >= Execution &&
                       InternalExecutionEnd >= InternalExecutionStart &&
                       Released >= InternalExecutionEnd &&
                       BusinessEnd == 0;

            if (ExecutionIgnored && !Saved)
                return SaveStart == 0 &&
                       SaveEnd == 0 &&
                       Arrival >= BusinessStart &&
                       Execution == 0 &&
                       InternalExecutionStart == 0 &&
                       InternalExecutionEnd == 0 &&
                       Released >= Arrival &&
                       BusinessEnd >= Arrival;

            if (ExecutionIgnored)
                return SaveStart >= BusinessStart &&
                       SaveEnd >= SaveStart &&
                       Arrival >= SaveEnd &&
                       Execution == 0 &&
                       InternalExecutionStart == 0 &&
                       InternalExecutionEnd == 0 &&
                       BusinessEnd >= Arrival;

            if (!Saved)
                return SaveStart == 0 &&
                       SaveEnd == 0 &&
                       Arrival >= BusinessStart &&
                       Execution >= Arrival &&
                       InternalExecutionStart >= Execution &&
                       InternalExecutionEnd >= InternalExecutionStart &&
                       BusinessEnd >= InternalExecutionEnd;

            return SaveStart >= BusinessStart &&
                   SaveEnd >= SaveStart &&
                   Arrival >= SaveEnd &&
                   Execution >= Arrival &&
                   InternalExecutionStart >= Execution &&
                   InternalExecutionEnd >= InternalExecutionStart &&
                   BusinessEnd >= InternalExecutionEnd;
        }

        public string TraceTimes()
        {
            var s = $"FromDbOrReceiver: {FromDbOrReceiver}, ExecutionIgnored: {ExecutionIgnored}, Saved: {SaveStart != 0}.";
            return $"{s} " +
                   $"BusinessStart:          {BusinessStart} " +
                   $"SaveStart:              {SaveStart} " +
                   $"SaveEnd:                {SaveEnd} " +
                   $"Arrival:                {Arrival} " +
                   $"Execution:              {Execution} " +
                   $"InternalExecutionStart: {InternalExecutionStart} " +
                   $"InternalExecutionEnd:   {InternalExecutionEnd} " +
                   $"BusinessEnd:            {BusinessEnd}";
        }
    }
    #endregion
}