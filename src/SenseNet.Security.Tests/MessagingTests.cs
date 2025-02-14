﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Diagnostics;
using SenseNet.Security.Data;
using SenseNet.Security.Tests.TestPortal;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;
using System.Collections.Concurrent;
using SenseNet.Extensions.DependencyInjection;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class MessagingTests : TestBase
    {
        private Context _context;
        public TestContext TestContext { get; set; }

        private SnTrace.Operation _snTraceOperation;
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

        //===================================================================

        [TestMethod]
        public void Messaging_MessageSender()
        {
            SnLog.Instance = new TestLogger();

            //---- Ensure test data
            var entities = CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = CreateTestAces();
            var storage = new DatabaseStorage
            {
                Aces = aces,
                Memberships = memberships,
                Entities = entities,
                Messages = new List<Tuple<int, DateTime, byte[]>>()
            };

            //---- Start the system
            var msgProvider = new TestMessageProvider(DiTools.CreateMessageSenderManager());
            msgProvider.MessageReceived += MsgProvider_MessageReceived;
            msgProvider.InitializeAsync(CancellationToken.None).GetAwaiter().GetResult();

            var securitySystem = Context.StartTheSystem(new MemoryDataProviderForMessagingTests(storage), msgProvider);

            _context = new Context(TestUser.User1, securitySystem);

            // small activity from me
            var activity1 = new TestActivity();
            activity1.Execute(_context.Security);

            // small activity from another
            var activity2 = new TestActivity
            {
                Sender = new TestMessageSender {ComputerID = Environment.MachineName, InstanceID = "AnotherAppDomain"}
            };
            activity2.Execute(_context.Security);

            Assert.AreEqual("true, false", string.Join(", ", msgProvider.ReceiverMessages));
        }
        private void MsgProvider_MessageReceived(object sender, MessageReceivedEventArgs args)
        {
            var msgProvider = (TestMessageProvider) sender;
            msgProvider.ReceiverMessages.Add(msgProvider.MessageSenderManager.IsMe(args.Message.Sender).ToString().ToLower());
        }

        [TestMethod]
        public void Messaging_BigActivity()
        {
            SnLog.Instance = new TestLogger();

            //---- Ensure test data
            var entities = CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = CreateTestAces();
            var storage = new DatabaseStorage
            {
                Aces = aces,
                Memberships = memberships,
                Entities = entities,
                Messages = new List<Tuple<int, DateTime, byte[]>>()
            };

            //---- Start the system
            var msgProvider = new TestMessageProvider(DiTools.CreateMessageSenderManager());
            msgProvider.InitializeAsync(CancellationToken.None).GetAwaiter().GetResult();
            var securitySystem = Context.StartTheSystem(new MemoryDataProviderForMessagingTests(storage), msgProvider,
                configureServices: services =>
                {
                    services.AddSecurityMessageType<TestActivity>();
                });

            _context = new Context(TestUser.User1, securitySystem);

            // small activity
            var smallActivity = new TestActivity();
            smallActivity.Execute(_context.Security);
            var smallActivityId = smallActivity.Id;

            // large activity
            var largeActivity = new TestActivity { Body = new string('*', securitySystem.MessagingOptions.DistributableSecurityActivityMaxSize + 1) };
            largeActivity.Execute(_context.Security);
            var largeActivityId = largeActivity.Id;

            // check the logger
            var expected = string.Format("Send: TestActivity, Applied: #{0}, " +
                                         "Send: BigActivityMessage, LoadMessage: TestActivity#{1}, Applied: #{1}",
                smallActivityId, largeActivityId);

            var testLogger = (TestLogger) SnLog.Instance;
            var actual = string.Join(", ", testLogger.InformationEvents);
            Assert.AreEqual(expected, actual);
        }

        public static ConcurrentDictionary<int, StoredSecurityEntity> CreateTestEntities()
        {
            var storage = new ConcurrentDictionary<int, StoredSecurityEntity>();
            var u1 = TestUser.User1;

            CreateEntity("E1", null, u1, storage);
            {
                CreateEntity("E2", "E1", u1, storage);
                {
                    CreateEntity("E5", "E2", u1, storage);
                    {
                        CreateEntity("E14", "E5", u1, storage);
                        {
                            CreateEntity("E50", "E14", u1, storage);
                            {
                                CreateEntity("E51", "E50", u1, storage);
                                {
                                    CreateEntity("E52", "E51", u1, storage);
                                }
                                CreateEntity("E53", "E50", u1, storage);
                            }
                        }
                        CreateEntity("E15", "E5", u1, storage);
                    }
                    CreateEntity("E6", "E2", u1, storage);
                    {
                        CreateEntity("E16", "E6", u1, storage);
                        CreateEntity("E17", "E6", u1, storage);
                    }
                    CreateEntity("E7", "E2", u1, storage);
                    {
                        CreateEntity("E18", "E7", u1, storage);
                        CreateEntity("E19", "E7", u1, storage);
                    }
                }
                CreateEntity("E3", "E1", u1, storage);
                {
                    CreateEntity("E8", "E3", u1, storage);
                    {
                        CreateEntity("E20", "E8", u1, storage);
                        CreateEntity("E21", "E8", u1, storage);
                    }
                    CreateEntity("E9", "E3", u1, storage);
                    CreateEntity("E10", "E3", u1, storage);
                }
                CreateEntity("E4", "E1", u1, storage);
                {
                    CreateEntity("E11", "E4", u1, storage);
                    CreateEntity("E12", "E4", u1, storage);
                    {
                        CreateEntity("E30", "E12", u1, storage);
                        {
                            CreateEntity("E31", "E30", u1, storage);
                            {
                                CreateEntity("E33", "E31", u1, storage);
                                CreateEntity("E34", "E31", u1, storage);
                                {
                                    CreateEntity("E40", "E34", u1, storage);
                                    CreateEntity("E43", "E34", u1, storage);
                                }
                            }
                            CreateEntity("E32", "E30", u1, storage);
                            {
                                CreateEntity("E35", "E32", u1, storage);
                                {
                                    CreateEntity("E41", "E35", u1, storage);
                                    {
                                        CreateEntity("E42", "E41", u1, storage);
                                    }
                                }
                                CreateEntity("E36", "E32", u1, storage);
                                {
                                    CreateEntity("E37", "E36", u1, storage);
                                }
                            }
                        }
                    }
                    CreateEntity("E13", "E4", u1, storage);
                }
            }
            return storage;
        }
        private static void CreateEntity(string name, string parentName, TestUser owner,
            ConcurrentDictionary<int, StoredSecurityEntity> storage)
        {
            var entityId = Id(name);
            var parentEntityId = parentName == null ? default : Id(parentName);

            storage.TryGetValue(parentEntityId, out _);

            var entity = new StoredSecurityEntity
            {
                Id = entityId,
                ParentId = parentEntityId,
                IsInherited = true,
                OwnerId = owner.Id
            };
            storage[entityId] = entity;
        }

        public static List<StoredAce> CreateTestAces()
        {
            return new List<StoredAce>
            {
                new StoredAce { EntityId = Id("E1"), IdentityId = Id("G1"), LocalOnly = false, AllowBits = 0x0EF, DenyBits = 0x000 },
                new StoredAce { EntityId = Id("E1"), IdentityId = Id("U1"), LocalOnly = false, AllowBits = 0x0EE, DenyBits = 0x001 },
                new StoredAce { EntityId = Id("E3"), IdentityId = Id("G2"), LocalOnly = false, AllowBits = 0x0ED, DenyBits = 0x002 },
                new StoredAce { EntityId = Id("E5"), IdentityId = Id("G2"), LocalOnly = false, AllowBits = 0x0EC, DenyBits = 0x003 },
                new StoredAce { EntityId = Id("E5"), IdentityId = Id("U2"), LocalOnly = false, AllowBits = 0x0EB, DenyBits = 0x004 },
                new StoredAce { EntityId = Id("E50"), IdentityId = Id("G3"), LocalOnly = false, AllowBits = 0x0EA, DenyBits = 0x005 }
            };
        }

        private static int Id(string name)
        {
            return Tools.GetId(name);
        }


        [Serializable]
        private class TestActivity : SecurityActivity
        {
            public string Body { get; set; }

            protected override Task StoreAsync(SecurityContext context, CancellationToken cancel) { return Task.CompletedTask; }
            protected override void Apply(SecurityContext context)
            {
                SnLog.WriteInformation("Applied: #" + Id);
            }

            internal override bool ShouldWaitFor(SecurityActivity olderActivity)
            {
                return false;
            }


        }

        private class TestLogger : IEventLogger
        {
            public readonly List<string> InformationEvents = new List<string>();

            public void Write(object message, ICollection<string> categories, int priority, int eventId, TraceEventType severity, string title,
                IDictionary<string, object> properties)
            {
                // ReSharper disable once SwitchStatementMissingSomeCases
                switch (severity)
                {
                    case TraceEventType.Information:
                        InformationEvents.Add(message.ToString());
                        break;
                    default:
                        throw new NotSupportedException();
                }
            }
        }
        [Serializable]
        private class TestMessageSender : IMessageSender
        {
            public string ComputerID { get; set; }
            public string InstanceID { get;  set; }
        }

        private class TestMessageProvider : IMessageProvider
        {
            public string ReceiverName => "TestMessageProvider";
            public int IncomingMessageCount => 0;

            public IMessageSenderManager MessageSenderManager { get; }

            public List<string> ReceiverMessages { get; } = new List<string>();

            public TestMessageProvider(IMessageSenderManager messageSenderManager)
            {
                MessageSenderManager = messageSenderManager;
            }

            public Task InitializeAsync(CancellationToken cancel) => Task.CompletedTask;

            public void SendMessage(IDistributedMessage message)
            {
                SnLog.WriteInformation("Send: " + message.GetType().Name);
                if (message is TestActivity originalActivity)
                    message = new TestActivity {Id = originalActivity.Id, Sender = originalActivity.Sender};
                MessageReceived?.Invoke(this, new MessageReceivedEventArgs(message));
            }
            public void Start(DateTime startingTheSystem)
            {
            }
            public void Start()
            {
            }
            public void Stop()
            {
            }
            public void Purge()
            {
            }
            public void ShutDown()
            {
            }

            public event MessageReceivedEventHandler MessageReceived;

            public event ReceiveExceptionEventHandler ReceiveException;

            public event SendExceptionEventHandler SendException;
        }
        private class MemoryDataProviderForMessagingTests : MemoryDataProvider
        {
            public MemoryDataProviderForMessagingTests(DatabaseStorage storage) : base(storage) { }
            [Obsolete("Use async version instead.")]
            public override SecurityActivity LoadSecurityActivity(int id)
            {
                return LoadSecurityActivityAsync(id, CancellationToken.None).GetAwaiter().GetResult();
            }
            public override async Task<SecurityActivity> LoadSecurityActivityAsync(int id, CancellationToken cancel)
            {
                var activity = await base.LoadSecurityActivityAsync(id, cancel).ConfigureAwait(false);
                SnLog.WriteInformation($"LoadMessage: {activity.GetType().Name}#{id}");
                return activity;
            }
        }
    }
}
