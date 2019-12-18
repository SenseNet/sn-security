using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Diagnostics;
using SenseNet.Security.Data;
using SenseNet.Security.Tests.TestPortal;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class MessagingTests
    {
        private Context _context;
        public TestContext TestContext { get; set; }

        [TestCleanup]
        public void Finishtest()
        {
            Tools.CheckIntegrity(TestContext.TestName, _context.Security);
        }

        //===================================================================

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
            var msgProvider = new TestMessageProvider();
            msgProvider.Initialize();
            Context.StartTheSystem(new MemoryDataProviderForMessagingTests(storage), msgProvider);

            _context = new Context(TestUser.User1);

            // small activity
            var smallActivity = new TestActivity();
            smallActivity.Execute(_context.Security);
            var smallActivityId = smallActivity.Id;

            // large activity
            var largeActivity = new TestActivity { Body = new string('*', Configuration.Messaging.DistributableSecurityActivityMaxSize + 1) };
            largeActivity.Execute(_context.Security);
            var largeActivityId = largeActivity.Id;

            // check the logger
            var expected = string.Format("Executing unprocessed security activities., " +
                                         "Send: TestActivity, Applied: #{0}, " +
                                         "Send: BigActivityMessage, LoadMessage: TestActivity#{1}, Applied: #{1}",
                smallActivityId, largeActivityId);

            var testLogger = (TestLogger) SnLog.Instance;
            var actual = string.Join(", ", testLogger.Informations);
            Assert.AreEqual(expected, actual);
        }

        public static Dictionary<int, StoredSecurityEntity> CreateTestEntities()
        {
            var storage = new Dictionary<int, StoredSecurityEntity>();
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
            Dictionary<int, StoredSecurityEntity> storage)
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

            protected override void Store(SecurityContext context) { }
            protected override void Apply(SecurityContext context)
            {
                SnLog.WriteInformation("Applied: #" + this.Id);
            }

            internal override bool MustWaitFor(SecurityActivity olderActivity)
            {
                return false;
            }


        }

        private class TestLogger : IEventLogger
        {
            public readonly List<string> Informations = new List<string>();

            public void Write(object message, ICollection<string> categories, int priority, int eventId, TraceEventType severity, string title,
                IDictionary<string, object> properties)
            {
                // ReSharper disable once SwitchStatementMissingSomeCases
                switch (severity)
                {
                    case TraceEventType.Information:
                        Informations.Add(message.ToString());
                        break;
                    default:
                        throw new NotSupportedException();
                }
            }
        }
        private class TestMessageProvider : IMessageProvider
        {
            public string ReceiverName { get { return "TestMessageProvider"; } }
            public int IncomingMessageCount { get { return 0; } }

            public void Initialize() {}

            public void SendMessage(IDistributedMessage message)
            {
                SnLog.WriteInformation("Send: " + message.GetType().Name);

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

#pragma warning disable 67
            public event ReceiveExceptionEventHandler ReceiveException;
#pragma warning restore 67

#pragma warning disable 67
            public event SendExceptionEventHandler SendException;
#pragma warning restore 67
        }
        private class MemoryDataProviderForMessagingTests : MemoryDataProvider
        {
            public MemoryDataProviderForMessagingTests(DatabaseStorage storage) : base(storage) { }
            public override ISecurityDataProvider CreateNew()
            {
                return new MemoryDataProviderForMessagingTests(Storage);
            }
            public override SecurityActivity LoadSecurityActivity(int id)
            {
                var activity =  base.LoadSecurityActivity(id);

                SnLog.WriteInformation($"LoadMessage: {activity.GetType().Name}#{id}");

                return activity;
            }
        }
    }
}
