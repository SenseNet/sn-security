using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Diagnostics;
using SenseNet.Security.Data;
using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class SystemStartTests : TestBase
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
                Tools.CheckIntegrity(TestContext.TestName, _context.Security);
            }
            finally
            {
                _FinishTest(TestContext);
            }
        }

        //===================================================================

        [TestMethod]
        public void SystemStartAndPreloadStructures()
        {
            //---- Ensure test data
            var entities = CreateTestEntities();
            var groups = CreateTestGroups();
            //var memberships = Tools.CreateInMemoryMembershipTable("G1:U1,U2|G2:U3,U4|G3:U1,U3|G4:U4|G5:U5");
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities };

            //---- Start the system
            Context.StartTheSystem(new MemoryDataProvider(storage), new DefaultMessageProvider());

            //---- Start the request
            _context = new Context(TestUser.User1);

            //---- check cache
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)_context.Security.DataProvider);
            Assert.AreEqual(entities.Count, _context.Security.Cache.Entities.Count);
            Assert.AreEqual(entities.Count, dbAcc.Storage.Entities.Count);
            Assert.AreEqual(groups.Count, _context.Security.Cache.Groups.Count);
            Assert.AreEqual(memberships.Count, dbAcc.Storage.Memberships.Count);
            Assert.AreEqual(aces.Count, storage.Aces.Count);

            //---- check membership in the evaluator
            var s = Tools.ReplaceIds(_context.Security.Evaluator._traceMembership());
            const string expected = @"U1:[G1,G3]U2:[G1]U3:[G2,G3]U4:[G2,G4]U5:[G5]";
            Assert.AreEqual(expected, s.Replace(Environment.NewLine, "").Replace(" ", ""));

            //---- pre-load
            var id1 = Id("E1");
            var id3 = Id("E3");
            var id5 = Id("E5");
            var id50 = Id("E50");

            //---- check nearest holder ids
            var entityTable = _context.Security.Cache.Entities;
            Assert.AreEqual(id1, entityTable[Id("E1")].GetFirstAclId());
            Assert.AreEqual(id1, entityTable[Id("E2")].GetFirstAclId());
            Assert.AreEqual(id3, entityTable[Id("E3")].GetFirstAclId());
            Assert.AreEqual(id1, entityTable[Id("E4")].GetFirstAclId());
            Assert.AreEqual(id5, entityTable[Id("E5")].GetFirstAclId());
            Assert.AreEqual(id1, entityTable[Id("E6")].GetFirstAclId());
            Assert.AreEqual(id5, entityTable[Id("E14")].GetFirstAclId());
            Assert.AreEqual(id5, entityTable[Id("E15")].GetFirstAclId());
            Assert.AreEqual(id1, entityTable[Id("E16")].GetFirstAclId());
            Assert.AreEqual(id1, entityTable[Id("E17")].GetFirstAclId());
            Assert.AreEqual(id50, entityTable[Id("E50")].GetFirstAclId());
            Assert.AreEqual(id50, entityTable[Id("E51")].GetFirstAclId());
            Assert.AreEqual(id50, entityTable[Id("E52")].GetFirstAclId());
            Assert.AreEqual(id50, entityTable[Id("E53")].GetFirstAclId());

            //---- check ACLs in the evaluator
            var allAcls = Tools.CollectAllAcls(_context.Security);
            Assert.AreEqual(4, allAcls.Count);
            var acl1 = GetAcl(allAcls, id1);
            var acl3 = GetAcl(allAcls, id3);
            var acl5 = GetAcl(allAcls, id5);
            var acl50 = GetAcl(allAcls, id50);
            Assert.IsNull(acl1.Parent);
            Assert.IsNotNull(acl3.Parent);
            Assert.IsNotNull(acl5.Parent);
            Assert.IsNotNull(acl50.Parent);
            Assert.AreEqual(id1, acl3.Parent.EntityId);
            Assert.AreEqual(id1, acl5.Parent.EntityId);
            Assert.AreEqual(id5, acl50.Parent.EntityId);
        }
        private static AclInfo GetAcl(Dictionary<int, AclInfo> acls, int entityId)
        {
            acls.TryGetValue(entityId, out var acl);
            return acl;
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

        public static Dictionary<int, SecurityGroup> CreateTestGroups()
        {
            var storage = new Dictionary<int, SecurityGroup>();

            var g = new SecurityGroup(Id("G1")) { UserMemberIds = new List<int> { Id("U1"), Id("U2") } }; storage.Add(g.Id, g);
            g = new SecurityGroup(Id("G2")) { UserMemberIds = new List<int> { Id("U3"), Id("U4") } }; storage.Add(g.Id, g);
            g = new SecurityGroup(Id("G3")) { UserMemberIds = new List<int> { Id("U1"), Id("U3") } }; storage.Add(g.Id, g);
            g = new SecurityGroup(Id("G4")) { UserMemberIds = new List<int> { Id("U4") } }; storage.Add(g.Id, g);
            g = new SecurityGroup(Id("G5")) { UserMemberIds = new List<int> { Id("U5") } }; storage.Add(g.Id, g);

            return storage;
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


        [TestMethod]
        public void SystemStartAndShutdown()
        {
            //---- Ensure test data
            var entities = CreateTestEntities();
            var groups = CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities };

            //---- Start the system
            Context.StartTheSystem(new MemoryDataProvider(storage), new DefaultMessageProvider());
            var ctxAcc = new PrivateObject(SecuritySystem.Instance);
            var killed = (bool)ctxAcc.GetField("_killed");
            Assert.IsFalse(killed);

            //---- Start the request
            _context = new Context(TestUser.User1);

            //---- operation
            _context.Security.HasPermission(entities.First().Value.Id, PermissionType.Open);

            //---- kill the system
            SecuritySystem.Instance.Shutdown();

            //---- check killed state
            killed = (bool)ctxAcc.GetField("_killed");
            Assert.IsTrue(killed);
        }
    }
}
