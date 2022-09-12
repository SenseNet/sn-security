using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
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

            public TestMessageProvider(IMessageSenderManager messageSenderManager, Queue<byte[]> messageQueue,
                bool isReceiver) : base(messageSenderManager, Options.Create(new MessagingOptions()))
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
                var buffer = stream.GetBuffer();
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

        [TestMethod]
        public void Messaging_SendReceive()
        {
            var messageQueue = new Queue<byte[]>();
            var sourceSystem = CreateSecuritySystem("source", messageQueue, false);
            var targetSystem = CreateSecuritySystem("target", messageQueue, true);
            try
            {
                var user = TestUser.User1;
                var ctx = new SecurityContext(user, sourceSystem);
                ctx.CreateSecurityEntity(999, 1, user.Id);

                Assert.IsTrue(((MemoryDataProvider) sourceSystem.DataProvider).Storage.Entities.ContainsKey(999));
                Assert.IsFalse(((MemoryDataProvider) targetSystem.DataProvider).Storage.Entities.ContainsKey(999));
                Assert.AreEqual(1, messageQueue.Count);

                ((TestMessageProvider) targetSystem.MessageProvider).ReceiveOne();

                Assert.AreEqual(0, messageQueue.Count);
                Thread.Sleep(200);
                Assert.IsTrue(((MemoryDataProvider)sourceSystem.DataProvider).Storage.Entities.ContainsKey(999));
                Assert.IsTrue(((MemoryDataProvider) targetSystem.DataProvider).Storage.Entities.ContainsKey(999));
            }
            finally
            {
                sourceSystem.Shutdown();
                targetSystem.Shutdown();
            }
        }

        private SecuritySystem CreateSecuritySystem(string instanceName, Queue<byte[]> messageQueue, bool isReceiver)
        {
            var entities = SystemStartTests.CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = SystemStartTests.CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities, Messages = new List<Tuple<int, DateTime, byte[]>>() };

            var messageSenderManager = new MessageSenderManager(null, instanceName);
            var securitySystem = new SecuritySystem(
                new MemoryDataProvider(storage),
                new TestMessageProvider(messageSenderManager, messageQueue, isReceiver),
                new MissingEntityHandler(),
                new SecurityConfiguration(),
                new MessagingOptions());

            securitySystem.StartAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();

            return securitySystem;
        }
    }
}
