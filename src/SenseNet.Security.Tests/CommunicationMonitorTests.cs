﻿using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Configuration;
using SenseNet.Security.Data;
using SenseNet.Security.Messaging;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class CommunicationMonitorTests : TestBase
    {
        private class TestDp : MemoryDataProvider
        {
            public bool IsCleanupSecurityActivitiesCalled;
            public bool IsGetLastSecurityActivityIdCalled;

            public TestDp(DatabaseStorage storage) : base(storage)
            {
            }

            [Obsolete("Use async version instead.")]
            public override void CleanupSecurityActivities(int timeLimitInMinutes)
            {
                CleanupSecurityActivitiesAsync(timeLimitInMinutes, CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            public override async Task CleanupSecurityActivitiesAsync(int timeLimitInMinutes, CancellationToken cancel)
            {
                await base.CleanupSecurityActivitiesAsync(timeLimitInMinutes, cancel).ConfigureAwait(false);
                IsCleanupSecurityActivitiesCalled = true;
            }

            [Obsolete("Use async version instead.")]
            public override int GetLastSecurityActivityId(DateTime startedTime)
            {
                return GetLastSecurityActivityIdAsync(startedTime, CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            public override async Task<int> GetLastSecurityActivityIdAsync(DateTime startedTime, CancellationToken cancel)
            {
                var result = await base.GetLastSecurityActivityIdAsync(startedTime, cancel).ConfigureAwait(false);
                IsGetLastSecurityActivityIdCalled = true;
                return result;
            }
        }

        [TestMethod]
        public void CommunicationMonitor_HearthBeat()
        {
            var testDp = new TestDp(DatabaseStorage.CreateEmpty());
            var messageProvider = new DefaultMessageProvider(new MessageSenderManager());
            var missingEntityHandler = new MissingEntityHandler();
            var messagingOptions = Options.Create(new MessagingOptions()
            {
                CommunicationMonitorRunningPeriodInSeconds = 1
            });
            var securitySystem = new SecuritySystem(testDp, messageProvider, missingEntityHandler,
                new SecurityConfiguration(), messagingOptions.Value);
            var dataHandler = new DataHandler(testDp, messagingOptions);
            var communicationMonitor = new CommunicationMonitor(dataHandler, messagingOptions);
            var activityHistory = new SecurityActivityHistoryController();
            var securityActivityQueue = new SecurityActivityQueue(securitySystem, communicationMonitor, dataHandler, activityHistory);

            // ACTION
            var communicationMonitorAcc = new ObjectAccessor(communicationMonitor);
            communicationMonitorAcc.Invoke("Timer_Elapsed");

            // ASSERT
            Assert.IsTrue(testDp.IsCleanupSecurityActivitiesCalled);
            Assert.IsTrue(testDp.IsGetLastSecurityActivityIdCalled);
        }
    }
}
