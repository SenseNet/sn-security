﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Extensions.DependencyInjection;
using SenseNet.Security.Configuration;
using SenseNet.Security.Data;
using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class MessagingTests2 : TestBase
    {
        #region Classes

        private class TestMessageProvider:MessageProviderBase
        {
            private Queue<byte[]> _messageQueue;
            private bool _isReceiver;

            public TestMessageProvider(IMessageSenderManager messageSenderManager, ISecurityMessageFormatter messageFormatter,
                Queue<byte[]> messageQueue, bool isReceiver)
                : base(messageSenderManager, messageFormatter, Options.Create(new MessagingOptions()), 
                    NullLogger<MessageProviderBase>.Instance)
            {
                _messageQueue = messageQueue;
                _isReceiver = isReceiver;
            }

            public override string ReceiverName { get; } = "[receiverName]";
            public override void SendMessage(IDistributedMessage message)
            {
                // This has to be set before sending the message so that receivers
                // can decide whether they should process it or not.
                message.MessageSent = DateTime.UtcNow;
                var stream = (MemoryStream)SerializeMessage(message);
                var buffer = stream.ToArray();
                _messageQueue.Enqueue(buffer);
            }

            internal void ReceiveOne()
            {
                var stream = new MemoryStream(_messageQueue.Dequeue());
                OnMessageReceived(stream);
            }
        }

        #endregion

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
                //CheckIntegrity(TestContext.TestName, _context.Security);
            }
            finally
            {
                _FinishTest(TestContext);
            }
        }

        //[TestMethod]
        // This test cannot work with MemoryDataProvider because all activities are fully executed.
        // See the public Task<SecurityActivityExecutionLock> AcquireSecurityActivityExecutionLockAsync(SecurityActivity, int, CancellationToken)
        public async Task Messaging_SendReceive()
        {
            var messageQueue = new Queue<byte[]>();
            var sourceSystem = CreateSecuritySystem("source", messageQueue, false);
            var targetSystem = CreateSecuritySystem("target", messageQueue, true);
            try
            {
                // It should be the same in a production environment, but in this case the difference is useful,
                // because it is possible to detect the operation that modifies the database.
                Assert.AreNotSame(((MemoryDataProvider) sourceSystem.DataProvider).Storage.Entities,
                    ((MemoryDataProvider) targetSystem.DataProvider).Storage.Entities);

                var user = TestUser.User1;
                var ctx = new SecurityContext(user, sourceSystem);
                await ctx.CreateSecurityEntityAsync(999, 1, user.Id, CancellationToken.None)
                    .ConfigureAwait(false);

                Assert.IsTrue(sourceSystem.Cache.Entities.ContainsKey(999));
                Assert.IsFalse(targetSystem.Cache.Entities.ContainsKey(999));
                Assert.AreEqual(1, messageQueue.Count);

                ((TestMessageProvider) targetSystem.MessageProvider).ReceiveOne();

                Assert.AreEqual(0, messageQueue.Count);
                await Task.Delay(1000);
                Assert.IsTrue(sourceSystem.Cache.Entities.ContainsKey(999));
                Assert.IsTrue(targetSystem.Cache.Entities.ContainsKey(999));
                // Source system executes the activity with a database operation
                Assert.IsTrue(((MemoryDataProvider)sourceSystem.DataProvider).Storage.Entities.ContainsKey(999));
                // Target system executes the activity without a database operation
                Assert.IsFalse(((MemoryDataProvider)targetSystem.DataProvider).Storage.Entities.ContainsKey(999));
            }
            finally
            {
                sourceSystem.Shutdown();
                targetSystem.Shutdown();
            }
        }

        private SecuritySystem CreateSecuritySystem(string instanceName, Queue<byte[]> messageQueue, bool isReceiver)
        {
            var services = new ServiceCollection()
                .AddLogging()
                .AddDefaultSecurityMessageTypes()
                .AddSingleton<ISecurityMessageFormatter, SnSecurityMessageFormatter>()
                .BuildServiceProvider();

            var entities = SystemStartTests.CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = SystemStartTests.CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities, Messages = new List<Tuple<int, DateTime, byte[]>>() };

            var securitySystem = new SecuritySystem(
                new MemoryDataProvider(storage),
                new TestMessageProvider(
                    DiTools.CreateMessageSenderManager(null, instanceName),
                    services.GetRequiredService<ISecurityMessageFormatter>(),
                    messageQueue,
                    isReceiver
                    ),
                services.GetRequiredService<ISecurityMessageFormatter>(),
                new MissingEntityHandler(),
                Options.Create(new SecurityConfiguration()),
                Options.Create(new MessagingOptions()),
                services.GetRequiredService<ILogger<SecuritySystem>>());

            securitySystem.StartAsync(CancellationToken.None).GetAwaiter().GetResult();

            return securitySystem;
        }
    }
}
