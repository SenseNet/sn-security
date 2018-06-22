using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.EF6SecurityStore;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    // ReSharper disable once InconsistentNaming
    [TestClass]
    public class EF6Tests : TestCases
    {
        protected override ISecurityDataProvider GetDataProvider()
        {
            return new EF6SecurityDataProvider(connectionString:
                ConfigurationManager.ConnectionStrings["EF6SecurityStorage"].ConnectionString);
        }

        private SecurityStorage Db()
        {
            var providerAcc = new PrivateObject((EF6SecurityDataProvider)CurrentContext.Security.DataProvider);
            return (SecurityStorage)providerAcc.Invoke("Db");
        }
        protected override void CleanupMemberships()
        {
            Db().Database.ExecuteSqlCommand("DELETE FROM [EFMemberships]");
        }



        [TestMethod]
        public void EF6_LoadActivities_AtStart_DataHandlerLevel()
        {
            var sctx = CurrentContext.Security;
            var user1Id = TestUser.User1.Id;
            var rootEntityId = Id("E01");

            // create 30 activities
            sctx.CreateSecurityEntity(rootEntityId, default(int), user1Id);
            for (int entityId = rootEntityId + 1; entityId < rootEntityId + 31; entityId++)
                sctx.CreateSecurityEntity(entityId, rootEntityId, user1Id);

            var lastId = Db().ExecuteTestScript<int>("select top 1 Id from [EFMessages] order by Id desc").First();


            // test0: initial
            var expectedCs0 = new CompletionState { LastActivityId = lastId };
            var cs0 = DataHandler.LoadCompletionState(sctx.DataProvider, out var dbId0);

            Assert.AreEqual(lastId, dbId0);
            Assert.AreEqual(expectedCs0.ToString(), cs0.ToString());


            // test1: create unprocessed activities: set "wait" on 4 continuous activity (except last) + 2 gaps before
            Db().ExecuteTestScript(@"declare @last int
                select top 1 @last = Id from [EFMessages] order by Id desc
                UPDATE EFMessages set ExecutionState = 'Executing'
                    where Id in (@last-1, @last-2, @last-3, @last-4, @last-6, @last-9)
                ");

            var expectedCs1 = new CompletionState
            {
                LastActivityId = lastId,
                Gaps = new[] { lastId - 9, lastId - 6, lastId - 4, lastId - 3, lastId - 2, lastId - 1 }
            };
            var cs1 = DataHandler.LoadCompletionState(sctx.DataProvider, out var dbId1);

            Assert.AreEqual(dbId1, lastId);
            Assert.AreEqual(expectedCs1.ToString(), cs1.ToString());


            // test2: create unprocessed activities: set "wait" on last 5 continuous activity (except last) + 2 gaps before
            Db().ExecuteTestScript(@"declare @last int
                select top 1 @last = Id from [EFMessages] order by Id desc
                UPDATE EFMessages set ExecutionState = 'Executing'
                    where Id in (@last)
                ");

            var expectedCs2 = new CompletionState
            {
                LastActivityId = lastId - 5,
                Gaps = new[] { lastId - 9, lastId - 6 }
            };
            var cs2 = DataHandler.LoadCompletionState(sctx.DataProvider, out var dbId2);

            Assert.AreEqual(dbId2, lastId);
            Assert.AreEqual(expectedCs2.ToString(), cs2.ToString());
        }

        [TestMethod]
        public void EF6_LoadActivities_AtStart_ActivityQueueLevel()
        {
            var sctx = CurrentContext.Security;
            var user1Id = TestUser.User1.Id;
            var rootEntityId = Id("E01");

            // create 30 activities
            sctx.CreateSecurityEntity(rootEntityId, default(int), user1Id);
            for (int entityId = rootEntityId + 1; entityId < rootEntityId + 31; entityId++)
                sctx.CreateSecurityEntity(entityId, rootEntityId, user1Id);

            var lastId = Db().ExecuteTestScript<int>("select top 1 Id from [EFMessages] order by Id desc").First();


            // test0: initial state
            var expectedCs = new CompletionState { LastActivityId = lastId };
            var uncompleted = DataHandler.LoadCompletionState(SecurityContext.General.DataProvider, out var lastActivityIdFromDb);
            SecurityActivityQueue.Startup(uncompleted, lastActivityIdFromDb);
            var cs0 = SecurityActivityQueue.GetCurrentState().Termination;
            Assert.AreEqual(expectedCs.ToString(), cs0.ToString());


            // test1: create some unprocessed activities: 4 continuous activity (except last) + 2 gaps before
            //        last-2 and last-6 "Wait", the others "Executing" by another appdomain.
            Db().ExecuteTestScript(@"declare @last int
                select top 1 @last = Id from [EFMessages] order by Id desc
                UPDATE EFMessages set ExecutionState = 'Executing', LockedBy = 'AnotherComputer'
                    where Id in (@last-1, @last-3, @last-4, @last-9)
                UPDATE EFMessages set ExecutionState = 'Wait', LockedBy = null, LockedAt = null
                    where Id in (@last-2, @last-6)
                ");

            var expectedIsFromDb1 = String.Join(", ", new[] { lastId - 9, lastId - 4, lastId - 3, lastId - 1, lastId });
            uncompleted = DataHandler.LoadCompletionState(SecurityContext.General.DataProvider, out lastActivityIdFromDb);
            SecurityActivityQueue.Startup(uncompleted, lastActivityIdFromDb);
            var cs1 = SecurityActivityQueue.GetCurrentState().Termination;
            var idsFromDb1 = String.Join(", ", Db().GetUnprocessedActivityIds());
            Assert.AreEqual(expectedCs.ToString(), cs1.ToString());
            Assert.AreEqual(expectedIsFromDb1, idsFromDb1);

            // test2: create unprocessed activities: last 5 continuous activity + 2 gaps before
            //        last-2 and last-6 "Wait", the others "Executing" by another appdomain.
            Db().ExecuteTestScript(@"declare @last int
                select top 1 @last = Id from [EFMessages] order by Id desc
                UPDATE EFMessages set ExecutionState = 'Executing', LockedBy = 'AnotherComputer'
                    where Id in (@last, @last-1, @last-3, @last-4, @last-9)
                UPDATE EFMessages set ExecutionState = 'Wait', LockedBy = null, LockedAt = null
                    where Id in (@last-2, @last-6)
                ");

            var expectedIsFromDb2 = String.Join(", ", new[] { lastId - 9, lastId - 4, lastId - 3, lastId - 1, lastId, lastId });
            uncompleted = DataHandler.LoadCompletionState(SecurityContext.General.DataProvider, out lastActivityIdFromDb);
            SecurityActivityQueue.Startup(uncompleted, lastActivityIdFromDb);
            var cs2 = SecurityActivityQueue.GetCurrentState().Termination;
            var idsFromDb2 = String.Join(", ", Db().GetUnprocessedActivityIds());
            Assert.AreEqual(expectedCs.ToString(), cs2.ToString());
            Assert.AreEqual(expectedIsFromDb2, idsFromDb2);
        }

        [TestMethod]
        public void EF6_LoadActivities_RightDependencies()
        {
            var sctx = CurrentContext.Security;
            var user1Id = TestUser.User1.Id;

            // register some dependent activities
            // create a tree
            string waitingActivitiesDump;

            try
            {
                SecurityActivityQueue.__disableExecution();

                new CreateSecurityEntityActivity(Id("E01"), default(int), user1Id).Execute(sctx, false);
                {
                    new CreateSecurityEntityActivity(Id("E02"), Id("E01"), user1Id).Execute(sctx, false);
                    {
                        new CreateSecurityEntityActivity(Id("E03"), Id("E02"), user1Id).Execute(sctx, false);
                        {
                            new CreateSecurityEntityActivity(Id("E04"), Id("E03"), user1Id).Execute(sctx, false);
                            new CreateSecurityEntityActivity(Id("E05"), Id("E03"), user1Id).Execute(sctx, false);
                        }
                    }
                }
                // set acl
                new SetAclActivity(null, new List<int>(), new List<int> { Id("E111"), Id("E03") }).Execute(sctx, false);
                new SetAclActivity(null, new List<int>(), new List<int> { Id("E112"), Id("E113") }).Execute(sctx, false);
                new SetAclActivity(null, new List<int>(), new List<int> { Id("E113"), Id("E114") }).Execute(sctx, false);
                // delete a chain
                new DeleteSecurityEntityActivity(Id("E04")).Execute(sctx, false);
                new DeleteSecurityEntityActivity(Id("E03")).Execute(sctx, false);
                new DeleteSecurityEntityActivity(Id("E02")).Execute(sctx, false);

                // dump
                var waitingActivities = SecurityActivityQueue.__getWaitingSet();
                var x = waitingActivities.Select(a => "{"
                   + $"id:{a.Id}, w:[{String.Join(",", a.WaitingFor.Select(b => b.Id))}], wm:[{String.Join(",", a.WaitingForMe.Select(c => c.Id))}]"
                                                     + "}");
                waitingActivitiesDump = String.Join(",", x);
            }
            finally
            {
                SecurityActivityQueue.__enableExecution();
            }

            var lastId = Db().ExecuteTestScript<int>("select top 1 Id from [EFMessages] order by Id desc").First();
            var create1 = lastId - 10;
            var create2 = lastId - 9;
            var create3 = lastId - 8;
            var create4 = lastId - 7;
            var create5 = lastId - 6;
            var setAcl1 = lastId - 5;
            var setAcl2 = lastId - 4;
            var setAcl3 = lastId - 3;
            var delete1 = lastId - 2;
            var delete2 = lastId - 1;
            var delete3 = lastId;

            var expectedWaitingActivitiesDump =
                  "{id:" + create1 + ", w:[], wm:[" + create2 + "]},"
                + "{id:" + create2 + ", w:[" + create1 + "], wm:[" + create3 + "," + delete3 + "]},"
                + "{id:" + create3 + ", w:[" + create2 + "], wm:[" + create4 + "," + create5 + "," + setAcl1 + "," + delete2 + "]},"
                + "{id:" + create4 + ", w:[" + create3 + "], wm:[" + delete1 + "]},"
                + "{id:" + create5 + ", w:[" + create3 + "], wm:[]},"

                + "{id:" + setAcl1 + ", w:[" + create3 + "], wm:[]},"
                + "{id:" + setAcl2 + ", w:[], wm:[" + setAcl3 + "]},"
                + "{id:" + setAcl3 + ", w:[" + setAcl2 + "], wm:[]},"

                + "{id:" + delete1 + ", w:[" + create4 + "], wm:[]},"
                + "{id:" + delete2 + ", w:[" + create3 + "], wm:[]},"
                + "{id:" + delete3 + ", w:[" + create2 + "], wm:[]}";

            Assert.AreEqual(expectedWaitingActivitiesDump, waitingActivitiesDump);
        }

        [TestMethod]
        public void EF6_LoadActivities_SmartGapResolution()
        {
            var sb = new StringBuilder();
            CommunicationMonitor.Stop();
            var sctx = CurrentContext.Security;
            var user1Id = TestUser.User1.Id;
            var rootEntityId = Id("E01");

            // create some activities with gap
            sctx.CreateSecurityEntity(rootEntityId, default(int), user1Id);
            for (int entityId = rootEntityId + 1; entityId < rootEntityId + 11; entityId++)
            {
                sctx.CreateSecurityEntity(entityId, rootEntityId, user1Id);
                Db().ExecuteTestScript(@"
                    -- 2 gap
                    INSERT INTO EFMessages ([SavedBy], [SavedAt], [ExecutionState]) VALUES ('asdf1', GETDATE(),'Wait')
                    INSERT INTO EFMessages ([SavedBy], [SavedAt], [ExecutionState]) VALUES ('qwer1', GETDATE(),'Wait')
                    DELETE EFMessages WHERE Id in (select top 2 Id from [EFMessages] order by Id desc)");
            }

            // these are be unprocessed
            Db().ExecuteTestScript("UPDATE EFMessages set ExecutionState = 'Wait', LockedBy = null, LockedAt = null");

            sb.Clear();
            var uncompleted = DataHandler.LoadCompletionState(SecurityContext.General.DataProvider, out var lastActivityIdFromDb);
            SecurityActivityQueue.Startup(uncompleted, lastActivityIdFromDb);

            var cs1 = SecurityActivityQueue.GetCurrentCompletionState();

            // expectation: there is no any gap.
            Assert.AreEqual(0, cs1.Gaps.Length);

            // create a gap
            Db().ExecuteTestScript(@"
                    -- 2 gap
                    INSERT INTO EFMessages ([SavedBy], [SavedAt], [ExecutionState]) VALUES ('asdf1', GETDATE(),'Wait')
                    INSERT INTO EFMessages ([SavedBy], [SavedAt], [ExecutionState]) VALUES ('qwer1', GETDATE(),'Wait')
                    DELETE EFMessages WHERE Id in (select top 2 Id from [EFMessages] order by Id desc)
                    -- copy last
                    INSERT INTO EFMessages([SavedBy],[SavedAt],[ExecutionState],[LockedBy],[LockedAt],[Body])
                         SELECT TOP 1 [SavedBy],GETDATE(),[ExecutionState],[LockedBy],[LockedAt],[Body] FROM EFMessages ORDER BY Id DESC
                    -- 2 gap
                    INSERT INTO EFMessages ([SavedBy], [SavedAt], [ExecutionState]) VALUES ('asdf2', GETDATE(),'Wait')
                    INSERT INTO EFMessages ([SavedBy], [SavedAt], [ExecutionState]) VALUES ('qwer2', GETDATE(),'Wait')
                    DELETE EFMessages WHERE Id in (select top 2 Id from [EFMessages] order by Id desc)");

            // last activity
            sctx.CreateSecurityEntity(101, rootEntityId, user1Id);

            var cs2 = SecurityActivityQueue.GetCurrentCompletionState();
            Assert.AreEqual(4, cs2.Gaps.Length);
            Assert.AreEqual(cs1.LastActivityId + 6, cs2.LastActivityId);

            SecurityActivityQueue.HealthCheck();

            var cs3 = SecurityActivityQueue.GetCurrentCompletionState();
            Assert.AreEqual(0, cs3.Gaps.Length);
            Assert.AreEqual(cs2.LastActivityId, cs3.LastActivityId);

            CommunicationMonitor.Start();
        }

    }
}
