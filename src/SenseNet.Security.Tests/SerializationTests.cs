using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class SerializationTests : TestBase
    {
        /*********************************************************/
        /*                   MESSAGE HIERARCHY                   */
        /*********************************************************/
        // IDistributedMessage
        //     UnknownMessage
        //     DistributedMessage
        //         BigActivityMessage
        //         DebugMessage
        //             PingMessage
        //             PongMessage
        //         SecurityActivity
        //             CreateSecurityEntityActivity
        //             DeleteSecurityEntityActivity
        //             ModifySecurityEntityOwnerActivity
        //             MoveSecurityEntityActivity
        //             SetAclActivity
        //             MembershipActivity
        //                 AddUserToSecurityGroupsActivity
        //                 AddMembersToGroupActivity
        //                 RemoveUserFromSecurityGroupsActivity
        //                 RemoveMembersFromGroupActivity
        //                 DeleteUserActivity
        //                 DeleteIdentitiesActivity
        //                 DeleteGroupActivity
        /*********************************************************/

        private Type[] _messageTypes = new[]
        {

            // IDistributedMessage
            typeof(UnknownMessage),
            // DistributedMessage : IDistributedMessage
            typeof(BigActivityMessage),
            typeof(DebugMessage),
            typeof(PingMessage),
            typeof(PongMessage),
            // SecurityActivity : DistributedMessage
            typeof(CreateSecurityEntityActivity),
            typeof(DeleteSecurityEntityActivity),
            typeof(ModifySecurityEntityOwnerActivity),
            typeof(MoveSecurityEntityActivity),
            typeof(SetAclActivity),
            // MembershipActivity : SecurityActivity : DistributedMessage
            typeof(AddUserToSecurityGroupsActivity),
            typeof(AddMembersToGroupActivity),
            typeof(RemoveUserFromSecurityGroupsActivity),
            typeof(RemoveMembersFromGroupActivity),
            typeof(DeleteUserActivity),
            typeof(DeleteIdentitiesActivity),
            typeof(DeleteGroupActivity),
        };

        [TestMethod]
        public void Messaging_Serialization_DebugMessage()
        {
            var message = new DebugMessage { Message = "test message" };
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual("test message", deserialized.Message);
            });
        }
        [TestMethod]
        public void Messaging_Serialization_PingMessage()
        {
            var message = new PingMessage();
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual("PING", deserialized.Message);
            });
        }
        [TestMethod]
        public void Messaging_Serialization_PongMessage()
        {
            var message = new PongMessage();
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual("PONG", deserialized.Message);
            });
        }
        [TestMethod]
        public void Messaging_Serialization_BigActivityMessage()
        {
            var message = new BigActivityMessage {DatabaseId = 42};
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(42, deserialized.DatabaseId);
            });
        }


        [TestMethod]
        public void Messaging_Serialization_CreateSecurityEntityActivity()
        {
            var message = new CreateSecurityEntityActivity { EntityId = 42, ParentEntityId = 459, OwnerId = 987};
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(42, deserialized.EntityId);
                Assert.AreEqual(459, deserialized.ParentEntityId);
                Assert.AreEqual(987, deserialized.OwnerId);
            });
        }
        [TestMethod]
        public void Messaging_Serialization_DeleteSecurityEntityActivity()
        {
            var message = new DeleteSecurityEntityActivity { EntityId = 7348 };
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(7348, deserialized.EntityId);
            });
        }
        [TestMethod]
        public void Messaging_Serialization_ModifySecurityEntityOwnerActivity()
        {
            var message = new ModifySecurityEntityOwnerActivity { EntityId = 828, OwnerId = 3194 };
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(828, deserialized.EntityId);
                Assert.AreEqual(3194, deserialized.OwnerId);
            });
        }
        [TestMethod]
        public void Messaging_Serialization_MoveSecurityEntityActivity()
        {
            var message = new MoveSecurityEntityActivity { SourceId = 35454, TargetId = 134511};
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(35454, deserialized.SourceId);
                Assert.AreEqual(134511, deserialized.TargetId);
            });
        }
        [TestMethod]
        public void Messaging_Serialization_SetAclActivity()
        {
            var acls = new[]
            {
                new AclInfo
                {
                    EntityId = 123,
                    Inherits = true,
                    Entries = new List<AceInfo>
                    {
                        new AceInfo
                        {
                            AllowBits = ulong.MaxValue - ulong.MaxValue / 2,
                            DenyBits = ulong.MaxValue / 2,
                            EntryType = EntryType.Normal,
                            IdentityId = 456,
                            LocalOnly = false
                        },
                        new AceInfo
                        {
                            AllowBits = ulong.MaxValue - ulong.MaxValue / 2,
                            DenyBits = ulong.MaxValue / 2,
                            EntryType = EntryType.Normal,
                            IdentityId = 457,
                            LocalOnly = true
                        }
                    }
                }
            };
            var entries = new List<StoredAce>
            {
                new StoredAce
                {
                    EntityId = 123,
                    EntryType = EntryType.Normal,
                    IdentityId = 3456,
                    LocalOnly = false,
                    AllowBits = 0x000000FF,
                    DenyBits = 0xFF000000
                },
                new StoredAce
                {
                    EntityId = 123,
                    EntryType = EntryType.Normal,
                    IdentityId = 3457,
                    LocalOnly = true,
                    AllowBits = 0x0000007F,
                    DenyBits = 0x7F000000
                }
            };
            var entriesToRemove = new List<StoredAce>
            {
                new StoredAce
                {
                    EntityId = 123,
                    EntryType = EntryType.Normal,
                    IdentityId = 3458,
                    LocalOnly = true,
                },
                new StoredAce
                {
                    EntityId = 123,
                    EntryType = EntryType.Normal,
                    IdentityId = 3459,
                    LocalOnly = false,
                }
            };
            var message = new SetAclActivity
            {
                Acls = acls,
                Breaks = new List<int> { 12, 23 },
                UndoBreaks = new List<int> { 13, 24 },
                Entries = entries,
                EntriesToRemove = entriesToRemove,
                EmptyAcls = new List<int> { 45, 56 },
            };

            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(1, deserialized.Acls.Count());
                Assert.AreEqual(2, deserialized.Entries.Count);
                Assert.AreEqual(2, deserialized.EntriesToRemove.Count);
                Assert.AreEqual("12, 23", string.Join(", ",
                    deserialized.Breaks.Select(x => x.ToString())));
                Assert.AreEqual("13, 24", string.Join(", ",
                    deserialized.UndoBreaks.Select(x => x.ToString())));
                Assert.AreEqual("45, 56", string.Join(", ",
                    deserialized.EmptyAcls.Select(x => x.ToString())));
            });
        }


        [TestMethod]
        public void Messaging_Serialization_AddUserToSecurityGroupsActivity()
        {
            var message = new AddUserToSecurityGroupsActivity {UserId = 654, ParentGroups = new[] {123, 234}};
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(654, deserialized.UserId);
                Assert.AreEqual("123, 234", string.Join(", ",
                    deserialized.ParentGroups.Select(x => x.ToString())));
            });
        }
        [TestMethod]
        public void Messaging_Serialization_AddMembersToGroupActivity()
        {
            var message = new AddMembersToGroupActivity
            {
                GroupId = 65,
                UserMembers = new[] {13, 29},
                GroupMembers = new[] {53, 24},
                ParentGroups = new[] {68, 75},
            };
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(65, deserialized.GroupId);
                Assert.AreEqual("13, 29", string.Join(", ",
                    deserialized.UserMembers.Select(x => x.ToString())));
                Assert.AreEqual("53, 24", string.Join(", ",
                    deserialized.GroupMembers.Select(x => x.ToString())));
                Assert.AreEqual("68, 75", string.Join(", ",
                    deserialized.ParentGroups.Select(x => x.ToString())));
            });
        }
        [TestMethod]
        public void Messaging_Serialization_RemoveUserFromSecurityGroupsActivity()
        {
            var message = new RemoveUserFromSecurityGroupsActivity {UserId = 65, ParentGroups = new[] {68, 75}};
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(65, deserialized.UserId);
                Assert.AreEqual("68, 75", string.Join(", ",
                    deserialized.ParentGroups.Select(x => x.ToString())));
            });
        }
        [TestMethod]
        public void Messaging_Serialization_RemoveMembersFromGroupActivity()
        {
            var message = new RemoveMembersFromGroupActivity
            {
                GroupId = 65,
                UserMembers = new[] { 13, 29 },
                GroupMembers = new[] { 53, 24 },
                ParentGroups = new[] { 68, 75 },
            };
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(65, deserialized.GroupId);
                Assert.AreEqual("13, 29", string.Join(", ",
                    deserialized.UserMembers.Select(x => x.ToString())));
                Assert.AreEqual("53, 24", string.Join(", ",
                    deserialized.GroupMembers.Select(x => x.ToString())));
                Assert.AreEqual("68, 75", string.Join(", ",
                    deserialized.ParentGroups.Select(x => x.ToString())));
            });
        }
        [TestMethod]
        public void Messaging_Serialization_DeleteUserActivity()
        {
            var message = new DeleteUserActivity { UserId = 669};
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(669, deserialized.UserId);
            });
        }
        [TestMethod]
        public void Messaging_Serialization_DeleteIdentitiesActivity()
        {
            var message = new DeleteIdentitiesActivity { IdentityIds = new[] { 13, 29 } };
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual("13, 29", string.Join(", ",
                    deserialized.IdentityIds.Select(x => x.ToString())));
            });
        }
        [TestMethod]
        public void Messaging_Serialization_DeleteGroupActivity()
        {
            var message = new DeleteGroupActivity { GroupId = 998 };
            SerializationTest(message, (deserialized, text) =>
            {
                Assert.AreEqual(998, deserialized.GroupId);
            });
        }

        /* ============================================================================================== */

        private void SerializationTest<T>(T message, Action<T, string> checkReceived) where T : IDistributedMessage
        {
            //using (var stream = new FileStream(@"C:\Users\kavics\Desktop\setacl", FileMode.Create))
            //{
            //    var bf = new BinaryFormatter();
            //    bf.Serialize(stream, message);
            //}

            // simulate message completion
            message.MessageSent = DateTime.UtcNow;
            message.Sender = new MessageSender(Environment.MachineName, Guid.NewGuid().ToString());

            var formatter = new SnMessageFormatter(
                knownMessageTypes: _messageTypes.Select(t => new DistributedMessageType(t)),
                jsonConverters: Array.Empty<JsonConverter>());

            var serialized = formatter.Serialize(message);

            serialized.Position = 0;
            var text = new StreamReader(serialized).ReadToEnd();

            serialized.Position = 0;
            var deserialized = formatter.Deserialize(serialized);

            checkReceived((T)deserialized, text);
        }
    }
}
