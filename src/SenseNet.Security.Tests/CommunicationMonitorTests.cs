using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Data;
using SenseNet.Security.Messaging;
using SenseNet.Testing;

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

            public override void CleanupSecurityActivities(int timeLimitInMinutes)
            {
                base.CleanupSecurityActivities(timeLimitInMinutes);
                IsCleanupSecurityActivitiesCalled = true;
            }

            public override int GetLastSecurityActivityId(DateTime startedTime)
            {
                var result = base.GetLastSecurityActivityId(startedTime);
                IsGetLastSecurityActivityIdCalled = true;
                return result;
            }
        }

        [TestMethod]
        public void CommunicationMonitor_HearthBeat()
        {
            using (new Swindler<int>(1, () => Configuration.Messaging.CommunicationMonitorRunningPeriodInSeconds,
                value => Configuration.Messaging.CommunicationMonitorRunningPeriodInSeconds = value))
            {
                var testDp = new TestDp(DatabaseStorage.CreateEmpty());
                var messageProvider = new DefaultMessageProvider();
                var missingEntityHandler = new MissingEntityHandler();
                var securitySystem = new SecuritySystem(testDp, messageProvider, missingEntityHandler,
                    new SecurityConfiguration());
                var dataHandler = new DataHandler(testDp);
                var communicationMonitor = new CommunicationMonitor(dataHandler);
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
}
