using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Diagnostics;
using SenseNet.Extensions.DependencyInjection;
using SenseNet.Security.EFCSecurityStore.Configuration;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;
using SenseNet.Security.Tests;
using SenseNet.Security.Tests.TestPortal;
using SenseNet.Tools;

namespace SenseNet.Security.EFCSecurityStore.Tests
{
    // ReSharper disable once InconsistentNaming
    [TestClass]
    public class EFCTests : TestCases
    {
        protected override ISecurityDataProvider GetDataProvider()
        {
            return new EFCSecurityDataProvider(
                DiTools.CreateMessageSenderManager(),
                new DefaultRetrier(Options.Create(new RetrierOptions()), NullLogger<DefaultRetrier>.Instance),
                Options.Create(new DataOptions { ConnectionString = Configuration.Instance.GetConnectionString() }),
                NullLogger<EFCSecurityDataProvider>.Instance);
        }

        private SecurityStorage Db()
        {
            var providerAcc = new ObjectAccessor((EFCSecurityDataProvider)DataProvider);
            return (SecurityStorage)providerAcc.Invoke("Db");
        }

        protected override void CleanupMemberships()
        {
            //var providerAcc = new PrivateObject((EFCSecurityDataProvider) CurrentContext.Security.DataProvider);
            //var db = (SecurityStorage)providerAcc.Invoke("Db");
            //db.Database.ExecuteSqlCommand("DELETE FROM [EFMemberships]");

            var dp = CurrentContext.Security.SecuritySystem.DataProvider;
            foreach (var group in dp.LoadAllGroupsAsync(CancellationToken.None).GetAwaiter().GetResult())
            {
                dp.RemoveMembersAsync(group.Id, group.UserMemberIds,
                    group.Groups.Select(g => g.Id), CancellationToken.None).GetAwaiter().GetResult();
            }
        }

        private ISecurityActivityQueue SecurityActivityQueue => SecuritySystem.SecurityActivityQueue;

        [TestMethod]
        public void EFC_LoadActivities_AtStart_DataHandlerLevel()
        {
            var sCtx = CurrentContext.Security;
            var user1Id = TestUser.User1.Id;
            var rootEntityId = Id("E01");

            // create 30 activities
            sCtx.CreateSecurityEntity(rootEntityId, default, user1Id);
            for (var entityId = rootEntityId + 1; entityId < rootEntityId + 31; entityId++)
                sCtx.CreateSecurityEntity(entityId, rootEntityId, user1Id);

            var lastId = Db().ExecuteTestScript<int>("select top 1 Id as Value from [EFMessages] order by Id desc").First();


            // test0: initial
            var expectedCs0 = new CompletionState { LastActivityId = lastId };
            var cs0 = DataHandler_LoadCompletionState(out var dbId0);

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
            var cs1 = DataHandler_LoadCompletionState(out var dbId1);

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
            var cs2 = DataHandler_LoadCompletionState(out var dbId2);

            Assert.AreEqual(dbId2, lastId);
            Assert.AreEqual(expectedCs2.ToString(), cs2.ToString());
        }

        [TestMethod]
        public async Task EFC_LoadActivities_AtStart_ActivityQueueLevel()
        {
            var sCtx = CurrentContext.Security;
            var user1Id = TestUser.User1.Id;
            var rootEntityId = Id("E01");

            // create 30 activities
            sCtx.CreateSecurityEntity(rootEntityId, default, user1Id);
            for (var entityId = rootEntityId + 1; entityId < rootEntityId + 31; entityId++)
                sCtx.CreateSecurityEntity(entityId, rootEntityId, user1Id);

            var lastId = Db().ExecuteTestScript<int>("select top 1 Id as Value from [EFMessages] order by Id desc").First();


            // test0: initial state
            var expectedCs = new CompletionState { LastActivityId = lastId };
            var uncompleted = DataHandler_LoadCompletionState(out var lastActivityIdFromDb);
            SecurityActivityQueue.Startup(uncompleted, lastActivityIdFromDb);
            var cs0 = SecurityActivityQueue.GetCurrentCompletionState();
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

            var expectedIsFromDb1 = string.Join(", ", new[] { lastId - 9, lastId - 4, lastId - 3, lastId - 1, lastId });
            uncompleted = DataHandler_LoadCompletionState(out lastActivityIdFromDb);
            SecurityActivityQueue.Startup(uncompleted, lastActivityIdFromDb);
            await Task.Delay(200).ConfigureAwait(false);
            var cs1 = SecurityActivityQueue.GetCurrentCompletionState();
            var idsFromDb1 = string.Join(", ", await Db().GetUnprocessedActivityIdsAsync(CancellationToken.None).ConfigureAwait(false));
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

            var expectedIsFromDb2 = string.Join(", ", new[] { lastId - 9, lastId - 4, lastId - 3, lastId - 1, lastId, lastId });
            uncompleted = DataHandler_LoadCompletionState(out lastActivityIdFromDb);
            SecurityActivityQueue.Startup(uncompleted, lastActivityIdFromDb);
            await Task.Delay(200).ConfigureAwait(false);
            var cs2 = SecurityActivityQueue.GetCurrentCompletionState();
            var idsFromDb2 = string.Join(", ", await Db().GetUnprocessedActivityIdsAsync(CancellationToken.None).ConfigureAwait(false));
            Assert.AreEqual(expectedCs.ToString(), cs2.ToString());
            Assert.AreEqual(expectedIsFromDb2, idsFromDb2);
        }

        [TestMethod]
        public async Task EFC_LoadActivities_SmartGapResolution()
        {
            var sb = new StringBuilder();
            SecuritySystem.CommunicationMonitor.Stop();
            var sCtx = CurrentContext.Security;
            var user1Id = TestUser.User1.Id;
            var rootEntityId = Id("E01");

            // create some activities with gap
            var activity = new CreateSecurityEntityActivity(rootEntityId, default, user1Id);
            await this.SecuritySystem.DataHandler.SaveActivityAsync(activity, CancellationToken.None).ConfigureAwait(false);
            await this.SecuritySystem.DataHandler.SaveActivityAsync(activity, CancellationToken.None).ConfigureAwait(false);
            for (var entityId = rootEntityId + 1; entityId < rootEntityId + 11; entityId++)
            {
                activity = new CreateSecurityEntityActivity(entityId, rootEntityId, user1Id);
                await this.SecuritySystem.DataHandler.SaveActivityAsync(activity, CancellationToken.None).ConfigureAwait(false);
                Db().ExecuteTestScript(@"
                    -- 2 gap
                    INSERT INTO EFMessages ([SavedBy], [SavedAt], [ExecutionState]) VALUES ('asdf1', GETDATE(),'Wait')
                    INSERT INTO EFMessages ([SavedBy], [SavedAt], [ExecutionState]) VALUES ('qwer1', GETDATE(),'Wait')
                    DELETE EFMessages WHERE Id in (select top 2 Id from [EFMessages] order by Id desc)");
            }

            // these are be unprocessed
            Db().ExecuteTestScript("UPDATE EFMessages set ExecutionState = 'Wait', LockedBy = null, LockedAt = null");

            sb.Clear();
            var uncompleted = DataHandler_LoadCompletionState(out var lastActivityIdFromDb);
            SecurityActivityQueue.Startup(uncompleted, lastActivityIdFromDb);

            await Task.Delay(2000).ConfigureAwait(false);

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
            sCtx.CreateSecurityEntity(101, rootEntityId, user1Id);

            var cs2 = SecurityActivityQueue.GetCurrentCompletionState();
            Assert.AreEqual(4, cs2.Gaps.Length);
            Assert.AreEqual(cs1.LastActivityId + 6, cs2.LastActivityId);

            SecurityActivityQueue.HealthCheck();
            await Task.Delay(200).ConfigureAwait(false);

            var cs3 = SecurityActivityQueue.GetCurrentCompletionState();
            Assert.AreEqual(0, cs3.Gaps.Length);
            Assert.AreEqual(cs2.LastActivityId, cs3.LastActivityId);

            SecuritySystem.CommunicationMonitor.Start();
        }

        [TestMethod]
        public void EFC_Services_Register()
        {
            // part 1 ----------------------------------------------------------
            var services = new ServiceCollection()
                .AddLogging()
                .AddSenseNetRetrier()
                .AddSingleton<IMessageSenderManager, MessageSenderManager>();

            // WITHOUT configuration
            services.AddEFCSecurityDataProvider();

            var provider = services.BuildServiceProvider();
            var sdp = provider.GetRequiredService<ISecurityDataProvider>();

            Assert.IsTrue(sdp is EFCSecurityDataProvider);
            Assert.AreEqual(null, sdp.ConnectionString);
            Assert.IsNotNull(new ObjectAccessor(sdp).GetField("_messageSenderManager"));

            // part 2 ----------------------------------------------------------
            services = new ServiceCollection()
                .AddLogging()
                .AddSenseNetRetrier()
                .AddSingleton<IMessageSenderManager, MessageSenderManager>();

            // WITH configuration
            services.AddEFCSecurityDataProvider(options =>
            {
                options.ConnectionString = "test123";
                options.SqlCommandTimeout = 123;
            });

            provider = services.BuildServiceProvider();
            sdp = provider.GetRequiredService<ISecurityDataProvider>();

            Assert.IsTrue(sdp is EFCSecurityDataProvider);
            Assert.AreEqual("test123", sdp.ConnectionString);
            Assert.IsNotNull(new ObjectAccessor(sdp).GetField("_messageSenderManager"));
        }

        /* ======================================================================== */

        private CompletionState DataHandler_LoadCompletionState(out int lastDbId)
        {
            var dbResult = DataHandler.LoadCompletionStateAsync(CancellationToken.None).GetAwaiter().GetResult();
            lastDbId = dbResult.LastDatabaseId;
            return dbResult.CompletionState;
        }
    }
}
