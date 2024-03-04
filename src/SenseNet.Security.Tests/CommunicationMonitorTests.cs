using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Extensions.DependencyInjection;
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
            public override int GetLastSecurityActivityId()
            {
                return GetLastSecurityActivityIdAsync(CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            public override async Task<int> GetLastSecurityActivityIdAsync(CancellationToken cancel)
            {
                var result = await base.GetLastSecurityActivityIdAsync(cancel).ConfigureAwait(false);
                IsGetLastSecurityActivityIdCalled = true;
                return result;
            }
        }

        [TestMethod]
        public void CommunicationMonitor_Heartbeat()
        {
            var services = new ServiceCollection()
                .AddLogging()
                .AddDefaultSecurityMessageTypes()
                .AddSingleton<ISecurityMessageFormatter, SnSecurityMessageFormatter>()
                .BuildServiceProvider();

            var testDp = new TestDp(DatabaseStorage.CreateEmpty());
            var messageProvider = DiTools.CreateDefaultMessageProvider();
            var messageFormatter = services.GetRequiredService<ISecurityMessageFormatter>();
            var missingEntityHandler = new MissingEntityHandler();
            var securityConfiguration = Options.Create(new SecurityConfiguration());
            var messagingOptions = Options.Create(new MessagingOptions()
            {
                CommunicationMonitorRunningPeriodInSeconds = 1
            });
            var logger = services.GetRequiredService<ILogger<SecuritySystem>>();
            var securitySystem = new SecuritySystem(testDp, messageProvider, messageFormatter, missingEntityHandler,
                securityConfiguration, messagingOptions, logger);
            var dataHandler = new DataHandler(testDp, messagingOptions);
            var communicationMonitor = new CommunicationMonitor(dataHandler, messagingOptions);
            var activityHistory = new SecurityActivityHistoryController();
            var securityActivityQueue = new SecurityActivityQueue(dataHandler, communicationMonitor, activityHistory, logger);

            // ACTION
            var communicationMonitorAcc = new ObjectAccessor(communicationMonitor);
            communicationMonitorAcc.Invoke("Timer_Elapsed");

            // ASSERT
            Assert.IsTrue(testDp.IsCleanupSecurityActivitiesCalled);
            Assert.IsTrue(testDp.IsGetLastSecurityActivityIdCalled);
        }
    }
}
