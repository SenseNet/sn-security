using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.EF6SecurityStore;
using SenseNet.Security.Tests.TestPortal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
// ReSharper disable InconsistentNaming
// ReSharper disable UnusedVariable
// ReSharper disable UnusedMethodReturnValue.Local
// ReSharper disable RedundantExplicitParamsArrayCreation
// ReSharper disable CoVariantArrayConversion

namespace SenseNet.Security.Tests.EF6
{
    [TestClass]
    public class EF6MembershipTests
    {
        private Context _context;
        public TestContext TestContext { get; set; }


        private SecurityStorage Db()
        {
            var preloaded = System.Data.Entity.SqlServer.SqlProviderServices.Instance;
            return new SecurityStorage(120);
        }

        [TestInitialize]
        public void InitializeTest()
        {
            Db().CleanupDatabase();
        }

        [TestCleanup]
        public void FinishTest()
        {
            Tools.CheckIntegrity(TestContext.TestName, _context.Security);
        }

        private Context CreateDefaultContext()
        {
            return Tools.GetEmptyContext(TestUser.User1, new EF6SecurityDataProvider());
        }

        //=================================================================== for new API
/*
        [TestMethod]
        public void EF6_Membership2_LoadGroupsAndFlatten()
        {
            // init
            context = CreateDefaultContext();
            InitializeMembershipStorage(context.Security, "G1:U1,G2,G3|G2:U2,G4,G5|G3:U3|G4:U4|G5:U5");

            // test
            var groups = DataHandler.LoadAllGroups(context.Security.DataProvider);
            var membership = SecurityCache.FlattenUserMembership(groups);

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G3|U4:G1,G2,G4|U5:G1,G2,G5", DumpMembership(membership));
        }

        [TestMethod]
        public void EF6_Membership2_LoadGroupsAndFlatten_WithCircle()
        {
            // init
            context = CreateDefaultContext();
            InitializeMembershipStorage(context.Security, "G1:U1,G2,G3|G2:U2,G4,G5|G3:U3|G4:U4,G1|G5:U5");

            // test
            var groups = DataHandler.LoadAllGroups(context.Security.DataProvider);
            var membership = SecurityCache.FlattenUserMembership(groups);

            // check
            Assert.AreEqual("U1:G1,G2,G4|U2:G1,G2,G4|U3:G1,G2,G3,G4|U4:G1,G2,G4|U5:G1,G2,G4,G5", DumpMembership(membership));
        }

        private static InitializeMembershipStorage(SecurityContext context, string src)
        {
            context.DataProvider.SetMembers(
        }
*/
        //=================================================================== before new API

        [TestMethod]
        public void EF6_Membership_StoreSimpleGroup()
        {
            _context = CreateDefaultContext();
            var groupId = 101;
            var group = new TestGroup { Id = groupId, };
            group.SetGroupMembers(new TestGroup[0]);
            group.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 });
            group.SetGroupsWhereThisIsMember(new TestGroup[0]);

            //# storing a new totally completed group.
            AddOrModifySecurityGroup(_context.Security, group);

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId);
            Assert.AreEqual(groupId, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            Assert.AreEqual("U1:G1|U2:G1", DumpMembership(_context.Security));
        }
        [TestMethod]
        public void EF6_Membership_StoreTwoGroups()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 });
            group1.SetGroupMembers(new[] { group2 });
            group2.SetGroupMembers(new TestGroup[0]);
            group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetGroupsWhereThisIsMember(new[] { group1 });

            //# storing a new totally completed group.
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            // check
            Assert.AreEqual("U1:G1|U2:G1|U3:G1,G2|U4:G1,G2", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void EF6_Membership_StoreGroupCircle()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User5 }); group3.SetGroupMembers(new[] { group1 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });


            //# storing a new totally completed group.
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G1,G2,G3|U5:G1,G2,G3", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User5.Id));
        }


        [TestMethod]
        public void EF6_Membership_DeleteRootGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            //# deleting a group that is has member but it is not member of another one.
            _context.Security.DeleteSecurityGroup(groupId1);

            // check
            Assert.AreEqual("U3:G2|U4:G2", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.IsNull(loaded);

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void EF6_Membership_DeleteMemberGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            //# deleting a group that is member of another one
            group1.RemoveGroup(group2);
            _context.Security.DeleteSecurityGroup(group2.Id);

            // check
            Assert.AreEqual("U1:G1|U2:G1", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.IsNull(loaded);
        }
        [TestMethod]
        public void EF6_Membership_DeleteGroupFromCircle()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User5 }); group3.SetGroupMembers(new[] { group1 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });

            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);

            //# deleting a group that is an item of a circle
            group2.RemoveGroup(group3);
            _context.Security.DeleteSecurityGroup(group3.Id);

            // check
            Assert.AreEqual("U1:G1|U2:G1|U3:G1,G2|U4:G1,G2", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.IsNull(loaded);
        }
        [TestMethod]
        public void EF6_Membership_DeleteUnknownGroup()
        {
            _context = CreateDefaultContext();

            //# deleting an unknown group
            _context.Security.DeleteSecurityGroup(int.MaxValue);

        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EF6_Membership_DeleteInvalidGroup()
        {
            _context = CreateDefaultContext();

            //# deleting an invalid group
            _context.Security.DeleteSecurityGroup(default(int));

        }

        [TestMethod]
        public void EF6_Membership_DeleteIdentities()
        {
            _context = CreateDefaultContext();

            /*
             * G1: U1       +   G2, G3
             * G2: U2
             * G3: U3       +   G4
             * G4: U4, U5
             * G5: U2       +   G3
             */

            var group1 = TestGroup.CreateTestGroup(1);
            var group2 = TestGroup.CreateTestGroup(2);
            var group3 = TestGroup.CreateTestGroup(3);
            var group4 = TestGroup.CreateTestGroup(4);
            var group5 = TestGroup.CreateTestGroup(5);

            group1.SetGroupMembers(new [] { group2, group3 });
            group2.SetUserMembers(new [] { TestUser.User2 });
            group3.SetUserMembers(new [] { TestUser.User3 });
            group3.SetGroupMembers(new[] { group4 });
            group4.SetUserMembers(new[] { TestUser.User4, TestUser.User5 });
            group5.SetGroupMembers(new[] { group3 });
            group5.SetUserMembers(new[] { TestUser.User2 });

            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);
            AddOrModifySecurityGroup(_context.Security, group4);
            AddOrModifySecurityGroup(_context.Security, group5);

            // add some permissions
            var eid = TestEntity.GetId(33);
            _context.Security.CreateSecurityEntity(eid, 0, eid);
            Tools.SetAcl(_context.Security, "+E33|+G3:____________+++");
            Tools.SetAcl(_context.Security, "+E33|+U2:____________+++");

            // check before: ACLs
            var acl = _context.Security.GetAcl(eid);
            Assert.IsTrue(acl.Entries.Any(ace => ace.IdentityId == TestUser.User2.Id), "Permission entry for U2 is missing.");
            Assert.IsTrue(acl.Entries.Any(ace => ace.IdentityId == group3.Id), "Permission entry for G3 is missing.");

            // check before: membership
            Assert.AreEqual("U2:G1,G2,G5|U3:G1,G3,G5|U4:G1,G3,G4,G5|U5:G1,G3,G4,G5", DumpMembership(_context.Security));

            _context.Security.DeleteIdentities(new[]{group3.Id, TestUser.User2.Id});

            // check after: membership
            Assert.AreEqual("U4:G4|U5:G4", DumpMembership(_context.Security));

            // check after: ACLS (permissions should disappear)
            acl = _context.Security.GetAcl(eid);
            Assert.IsFalse(acl.Entries.Any(ace => ace.IdentityId == TestUser.User2.Id), "Permission entry for U2 did NOT disappear.");
            Assert.IsFalse(acl.Entries.Any(ace => ace.IdentityId == group3.Id), "Permission entry for G3 did NOT disappear.");

            // cleanup
            _context.Security.DeleteEntity(eid);
        }

        [TestMethod]
        public void EF6_Membership_AddUserToRootGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            //# Adding user and registering the change.
            group1.AddUser(TestUser.User3);
            _context.Security.AddUsersToSecurityGroup(group1.Id, new[] { TestUser.User3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));
        }
        [TestMethod]
        public void EF6_Membership_AddUserToMemberGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            //# Adding user and registering the change.
            group2.AddUser(TestUser.User3);
            _context.Security.AddUsersToSecurityGroup(group2.Id, new[] { TestUser.User3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G2", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void EF6_Membership_AddUserToGroupInCircle()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User5 }); group3.SetGroupMembers(new[] { group1 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });

            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);

            //# Adding user and registering the change.
            group1.AddUser(TestUser.User6);
            _context.Security.AddUsersToSecurityGroup(group1.Id, new[] { TestUser.User6.Id });


            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G1,G2,G3|U5:G1,G2,G3|U6:G1,G2,G3", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(3, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User6.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User5.Id));
        }

        [TestMethod]
        public void EF6_Membership_RemoveUserFromRootGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            //# Removing user and registering the change.
            group1.RemoveUser(TestUser.User2);
            _context.Security.RemoveUsersFromSecurityGroup(group1.Id, new[] { TestUser.User2.Id });

            // check
            Assert.AreEqual("U1:G1|U3:G1,G2|U4:G1,G2", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void EF6_Membership_RemoveUserFromMemberGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            //# Removing user and registering the change.
            group2.RemoveUser(TestUser.User4);
            _context.Security.RemoveUsersFromSecurityGroup(group2.Id, new[] { TestUser.User4.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1|U3:G1,G2", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void EF6_Membership_RemoveUserFromGroupInCircle()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User5 }); group3.SetGroupMembers(new[] { group1 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });

            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);

            //# Removing user and registering the change.
            group1.RemoveUser(TestUser.User2);
            _context.Security.RemoveUsersFromSecurityGroup(group1.Id, new[] { TestUser.User2.Id });

            // check
            Assert.AreEqual("U1:G1,G2,G3|U3:G1,G2,G3|U4:G1,G2,G3|U5:G1,G2,G3", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User5.Id));
        }


        [TestMethod]
        public void EF6_Membership_AddGroupToRootGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            var groupId3 = 103;
            var group3 = new TestGroup { Id = groupId3 };
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new TestGroup[0]); group3.SetGroupsWhereThisIsMember(new TestGroup[0]);
            AddOrModifySecurityGroup(_context.Security, group3);

            //# Adding group and registering the change.
            group1.SetGroupMembers(new[] { group2, group3 });
            group3.SetGroupsWhereThisIsMember(new[] { group1 }); // necessary only in test
            _context.Security.AddGroupsToSecurityGroup(group1.Id, new[] { group2.Id, group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G3", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void EF6_Membership_AddGroupToMemberGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            var groupId3 = 103;
            var group3 = new TestGroup { Id = groupId3 };
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new TestGroup[0]); group3.SetGroupsWhereThisIsMember(new TestGroup[0]);
            AddOrModifySecurityGroup(_context.Security, group3);

            //# Adding group and registering the change.
            group2.SetGroupMembers(new[] { group3 });
            group3.SetGroupsWhereThisIsMember(new[] { group2 }); // necessary only in test
            _context.Security.AddGroupsToSecurityGroup(group2.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G2,G3", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void EF6_Membership_AddGroupToGroupInCircle()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 });
            group1.SetGroupMembers(new[] { group2 });
            group2.SetGroupMembers(new[] { group3 });
            group3.SetGroupMembers(new[] { group1 });
            group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetGroupsWhereThisIsMember(new[] { group2 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);

            var groupId4 = 104;
            var group4 = new TestGroup { Id = groupId4, };
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 });
            group4.SetGroupMembers(new TestGroup[0]);
            group4.SetGroupsWhereThisIsMember(new TestGroup[0]);
            AddOrModifySecurityGroup(_context.Security, group4);

            //# Adding group and registering the change.
            group1.SetGroupMembers(new[] { group2, group4 });
            group4.SetGroupsWhereThisIsMember(new[] { group1 }); // necessary only in test
            _context.Security.AddGroupsToSecurityGroup(group1.Id, new[] { group2.Id, group4.Id });

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G1,G2,G3,G4", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }


        [TestMethod]
        public void EF6_Membership_RemoveGroupFromRootGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2, group3 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new TestGroup[0]); group3.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);

            //# Removing group and registering the change.
            group1.SetGroupMembers(new[] { group2 });
            group3.SetGroupsWhereThisIsMember(new TestGroup[0]); // necessary only in test
            _context.Security.RemoveGroupsFromSecurityGroup(group1.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G3", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void EF6_Membership_RemoveGroupFromMemberGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new TestGroup[0]); group3.SetGroupsWhereThisIsMember(new[] { group2 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);

            //# Removing group and registering the change.
            group2.SetGroupMembers(new TestGroup[0]);
            group3.SetGroupsWhereThisIsMember(new TestGroup[0]); // necessary only in test
            _context.Security.RemoveGroupsFromSecurityGroup(group2.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G3", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void EF6_Membership_RemoveGroupFromGroupInCircle()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var groupId4 = 104;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 });
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 });
            group1.AddGroup(group2);
            group1.AddGroup(group4);
            group2.AddGroup(group3);
            group3.AddGroup(group1);
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);
            AddOrModifySecurityGroup(_context.Security, group4);

            //# Removing group and registering the change.
            group1.RemoveGroup(group4);
            _context.Security.RemoveGroupsFromSecurityGroup(group1.Id, new[] { group4.Id });

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G4", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }


        [TestMethod]
        public void EF6_Membership_AddGroupChainToRootGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            var groupId3 = 103;
            var groupId4 = 104;
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new[] { group4 }); group3.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 }); group4.SetGroupMembers(new TestGroup[0]); group4.SetGroupsWhereThisIsMember(new[] { group3 });
            AddOrModifySecurityGroup(_context.Security, group3);
            AddOrModifySecurityGroup(_context.Security, group4);

            //# Adding group chain and registering the change.
            group1.SetGroupMembers(new[] { group2, group3 });
            group3.SetGroupsWhereThisIsMember(new[] { group1 }); // necessary only in test
            _context.Security.AddGroupsToSecurityGroup(group1.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G3|U4:G1,G3,G4", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void EF6_Membership_AddGroupChainToMemberGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);

            var groupId3 = 103;
            var groupId4 = 104;
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new[] { group4 }); group3.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 }); group4.SetGroupMembers(new TestGroup[0]); group4.SetGroupsWhereThisIsMember(new[] { group3 });
            AddOrModifySecurityGroup(_context.Security, group3);
            AddOrModifySecurityGroup(_context.Security, group4);

            //# Adding group chain and registering the change.
            group2.SetGroupMembers(new[] { group3 });
            group3.SetGroupsWhereThisIsMember(new[] { group2 }); // necessary only in test
            _context.Security.AddGroupsToSecurityGroup(group2.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G2,G3|U4:G1,G2,G3,G4", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void EF6_Membership_AddGroupChainToGroupInCircle()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new[] { group1 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });

            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);

            var groupId4 = 104;
            var groupId5 = 105;
            var group4 = new TestGroup { Id = groupId4 };
            var group5 = new TestGroup { Id = groupId5 };
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 }); group4.SetGroupMembers(new[] { group5 }); group4.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group5.SetUserMembers(new ISecurityUser[] { TestUser.User5 }); group5.SetGroupMembers(new TestGroup[0]); group4.SetGroupsWhereThisIsMember(new[] { group4 });
            AddOrModifySecurityGroup(_context.Security, group4);
            AddOrModifySecurityGroup(_context.Security, group5);

            //# Adding group and registering the change.
            group1.SetGroupMembers(new[] { group2, group4 });
            group4.SetGroupsWhereThisIsMember(new[] { group1 }); // necessary only in test
            _context.Security.AddGroupsToSecurityGroup(group1.Id, new[] { group4.Id });

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G1,G2,G3,G4|U5:G1,G2,G3,G4,G5", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId5);
            Assert.AreEqual(groupId5, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User5.Id));
        }

        [TestMethod]
        public void EF6_Membership_RemoveGroupChainFromRootGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var groupId4 = 104;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2, group3 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new[] { group4 }); group3.SetGroupsWhereThisIsMember(new[] { group1 });
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 }); group4.SetGroupMembers(new TestGroup[0]); group4.SetGroupsWhereThisIsMember(new[] { group3 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);
            AddOrModifySecurityGroup(_context.Security, group4);

            //# Removing group and registering the change.
            group1.SetGroupMembers(new[] { group2 });
            group3.SetGroupsWhereThisIsMember(new TestGroup[0]); // necessary only in test
            _context.Security.RemoveGroupsFromSecurityGroup(group1.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G3|U4:G3,G4", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void EF6_Membership_RemoveGroupChainFromMemberGroup()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var groupId4 = 104;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new[] { group4 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 }); group4.SetGroupMembers(new TestGroup[0]); group3.SetGroupsWhereThisIsMember(new[] { group3 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);
            AddOrModifySecurityGroup(_context.Security, group4);

            //# Removing group and registering the change.
            group2.SetGroupMembers(new TestGroup[0]);
            group3.SetGroupsWhereThisIsMember(new TestGroup[0]); // necessary only in test
            _context.Security.RemoveGroupsFromSecurityGroup(group2.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G3|U4:G3,G4", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void EF6_Membership_RemoveGroupChainFromGroupInCircle()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var groupId4 = 104;
            var groupId5 = 105;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            var group5 = new TestGroup { Id = groupId5 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 });
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 });
            group5.SetUserMembers(new ISecurityUser[] { TestUser.User5 });
            group1.AddGroup(group2);
            group2.AddGroup(group3);
            group3.AddGroup(group1);
            group4.AddGroup(group5);
            group1.AddGroup(group4);
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);
            AddOrModifySecurityGroup(_context.Security, group4);
            AddOrModifySecurityGroup(_context.Security, group5);

            //# Removing group and registering the change.
            group1.SetGroupMembers(new[] { group2 });
            group4.SetGroupsWhereThisIsMember(new TestGroup[0]);  // necessary only in test
            _context.Security.RemoveGroupsFromSecurityGroup(group1.Id, new[] { group4.Id });

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G4|U5:G4,G5", DumpMembership(_context.Security));

            var loaded = DataHandler.GetSecurityGroup(_context.Security, groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(_context.Security, groupId5);
            Assert.AreEqual(groupId5, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User5.Id));
        }

        [TestMethod]
        public void EF6_Membership_RemoveGroupThatContainsCircle()
        {
            Prepare_GroupThatContainsCircle_Test();
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G2,G3,G4,G5|U4:G1,G2,G3,G4,G5|U5:G1,G2,G3,G4,G5", DumpMembership(_context.Security));

            //# Removing group and registering the change.
            _context.Security.RemoveGroupsFromSecurityGroup(Id("G1"), new[] { Id("G2") });

            Assert.AreEqual("U1:G1|U2:G2|U3:G2,G3,G4,G5|U4:G2,G3,G4,G5|U5:G2,G3,G4,G5", DumpMembership(_context.Security));
        }
        [TestMethod]
        public void EF6_Membership_DeleteGroupThatContainsCircle()
        {
            Prepare_GroupThatContainsCircle_Test();
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G2,G3,G4,G5|U4:G1,G2,G3,G4,G5|U5:G1,G2,G3,G4,G5", DumpMembership(_context.Security));

            //# Deleting group and registering the change.
            _context.Security.DeleteSecurityGroup(Id("G2"));

            Assert.AreEqual("U1:G1|U3:G3,G4,G5|U4:G3,G4,G5|U5:G3,G4,G5", DumpMembership(_context.Security));
        }
        private Context Prepare_GroupThatContainsCircle_Test()
        {
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var groupId4 = 104;
            var groupId5 = 105;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            var group5 = new TestGroup { Id = groupId5 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 });
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 });
            group5.SetUserMembers(new ISecurityUser[] { TestUser.User5 });

            group1.AddGroup(group2);
            group2.AddGroup(group3);
            group3.AddGroup(group4);
            group4.AddGroup(group5);
            group5.AddGroup(group3);
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);
            AddOrModifySecurityGroup(_context.Security, group4);
            AddOrModifySecurityGroup(_context.Security, group5);

            return _context;
        }

        [TestMethod]
        public void EF6_Membership_Flattening()
        {
            // make two disjunct structure
            _context = CreateDefaultContext();
            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var groupId4 = 104;
            var groupId5 = 105;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            var group5 = new TestGroup { Id = groupId5 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 });
            group1.SetGroupMembers(new[] { group2 });
            group2.SetGroupMembers(new[] { group3 });
            group3.SetGroupMembers(new[] { group1 });
            group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetGroupsWhereThisIsMember(new[] { group2 });
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 });
            group5.SetUserMembers(new ISecurityUser[] { TestUser.User5 });
            group4.SetGroupMembers(new[] { group5 });
            group5.SetGroupsWhereThisIsMember(new[] { group4 });
            AddOrModifySecurityGroup(_context.Security, group1);
            AddOrModifySecurityGroup(_context.Security, group2);
            AddOrModifySecurityGroup(_context.Security, group3);
            AddOrModifySecurityGroup(_context.Security, group4);
            AddOrModifySecurityGroup(_context.Security, group5);

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G4|U5:G4,G5", DumpMembership(_context.Security));
        }

        [TestMethod]
        public void EF6_DynamicMembership_1()
        {
            var savedGroups = TestUser.User1.GetDynamicGroups(int.MaxValue); // for tests only
            try
            {
                _context = CreateDefaultContext();
                var repo = Tools.CreateRepository(_context.Security);
                // Test description:
                // U1 and U2 are in the G2, G3.
                // There is a group: G4.
                // In repository (see the SecurityTreeForTests.vsd) the second level nodes belong to a group: E2 - G1, E3 - G2, E4 - G3. For example these are the workspaces.
                // Every workspace's first node is secret (E5, E8, E11) so these are breaked but they have open permission for a group: G4.
                // Let the rule for dymanic group setting is the following:
                //     if the U1 user gets the secret node, she is in the G4 group if she has open permission for the parent workspace.

                Db()._cleanupMembership();
                Tools.SetMembership(_context.Security, "U1:G2,G3");

                Tools.SetAcl(_context.Security, "+E2|+G1:______________+");
                Tools.SetAcl(_context.Security, "+E3|+G2:______________+");
                Tools.SetAcl(_context.Security, "+E4|+G3:______________+");

                Tools.SetAcl(_context.Security, "-E5|+G4:______________+");
                Tools.SetAcl(_context.Security, "-E8|+G4:______________+");
                Tools.SetAcl(_context.Security, "-E11|+G4:______________+");

                //# User hasn't read permission so she is not in the G4 group
                TestUser.User1.SetDynamicGroups(null);
                Assert.IsFalse(_context.Security.HasPermission(Id("E5"), PermissionType.See));

                //# User hasn read permission on E3 so she is in the G4 group
                TestUser.User1.SetDynamicGroups(new[] { Id("G4") });
                Assert.IsTrue(_context.Security.HasPermission(Id("E8"), PermissionType.See));

                //# User hasn read permission on E4 so she is in the G4 group
                TestUser.User1.SetDynamicGroups(new[] { Id("G4") });
                Assert.IsTrue(_context.Security.HasPermission(Id("E11"), PermissionType.See));
            }
            finally
            {
                TestUser.User1.SetDynamicGroups(savedGroups);
            }
        }
        [TestMethod]
        public void EF6_DynamicMembership_FlattenDynamicGroups()
        {
            _context = Tools.GetEmptyContext(TestUser.User1);
            var ctx = _context.Security;

            // #1: Create the identity structure: G1(U1,G2), G2(U2, G3), G3(U3, G1), G4(U4, G5), G5(U5)

            var groupId1 = 101;
            var groupId2 = 102;
            var groupId3 = 103;
            var groupId4 = 104;
            var groupId5 = 105;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            var group5 = new TestGroup { Id = groupId5 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 });
            group1.SetGroupMembers(new[] { group2 });
            group2.SetGroupMembers(new[] { group3 });
            group3.SetGroupMembers(new[] { group1 });
            group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetGroupsWhereThisIsMember(new[] { group2 });
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 });
            group5.SetUserMembers(new ISecurityUser[] { TestUser.User5 });
            group4.SetGroupMembers(new[] { group5 });
            group5.SetGroupsWhereThisIsMember(new[] { group4 });
            AddOrModifySecurityGroup(ctx, group1);
            AddOrModifySecurityGroup(ctx, group2);
            AddOrModifySecurityGroup(ctx, group3);
            AddOrModifySecurityGroup(ctx, group4);
            AddOrModifySecurityGroup(ctx, group5);

            // #2: Set permissions on entity1 for each groups
            var entityId = Id("E1");
            ctx.CreateSecurityEntity(entityId, 0, int.MaxValue);

            var ed = ctx.CreateAclEditor();
            ed.Allow(entityId, group1.Id, false, new[] { PermissionType.Open, PermissionType.Custom01 });
            ed.Allow(entityId, group2.Id, false, new[] { PermissionType.Open, PermissionType.Custom02 });
            ed.Allow(entityId, group3.Id, false, new[] { PermissionType.Open, PermissionType.Custom03 });
            ed.Allow(entityId, group4.Id, false, new[] { PermissionType.Open, PermissionType.Custom04 });
            ed.Allow(entityId, group5.Id, false, new[] { PermissionType.Open, PermissionType.Custom05 });
            ed.Apply();

            // #3: Validate the initial conditions: User4 has only Open and Custom04
            ctx = new TestSecurityContext(TestUser.User4);
            Assert.IsFalse(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.Custom01));
            Assert.IsFalse(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.Custom02));
            Assert.IsFalse(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.Custom03));
            Assert.IsTrue(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.Custom04));
            Assert.IsFalse(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.Custom05));

            // #4: User4 is in the Group1 dynamically
            var backup = TestUser.User4.GetDynamicGroups(entityId);
            TestUser.User4.SetDynamicGroups(new[] { group1.Id });

            // #5 Check that the User4 has Open and Custom01-05 permissions
            try
            {
                Assert.IsTrue(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.Custom01));
                Assert.IsTrue(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.Custom02));
                Assert.IsTrue(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.Custom03));
                Assert.IsTrue(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.Custom04));
                Assert.IsFalse(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.Custom05));
            }
            finally
            {
                TestUser.User4.SetDynamicGroups(backup);
            }
        }

        //===========================================================================================================

        private static void AddOrModifySecurityGroup(TestSecurityContext ctx, TestGroup group)
        {
            ctx.AddMembersToSecurityGroup(group.Id, group.GetUserMembers().Select(u => u.Id).ToArray(), group.GetGroupMembers().Select(g => g.Id).ToArray(), group.GetGroupsWhereThisIsMember().Select(p => p.Id).ToArray());
        }

        private int Id(string name)
        {
            return Tools.GetId(name);
        }

        //internal static string DumpMembership(SecurityContext context)
        //{
        //    //var evaluatorAcc = new PrivateObject(context.Evaluator);
        //    var membership = context.Cache.Membership;

        //    var sb = new StringBuilder();

        //    foreach (var userId in membership.Keys.OrderBy(s => s))
        //    {
        //        sb.Append(GetUserName(userId)).Append(":");
        //        sb.Append(String.Join(",", membership[userId].Select(g => GetGroupName(g)).OrderBy(s => s)));
        //        sb.Append("|");
        //    }
        //    sb.Length--;
        //    return sb.ToString();
        //}
        internal static string DumpMembership(SecurityContext context)
        {
            return DumpMembership(context.Cache.Membership);
        }
        public static string DumpMembership(Dictionary<int, List<int>> membership)
        {
            if (membership.Count == 0)
                return String.Empty;

            var sb = new StringBuilder();
            foreach (var userId in membership.Keys.OrderBy(s => s))
            {
                sb.Append(GetUserName(userId)).Append(":");
                sb.Append(String.Join(",", membership[userId].Select(GetGroupName).OrderBy(s => s)));
                sb.Append("|");
            }
            sb.Length--;
            return sb.ToString();
        }

        private static string GetUserName(int userId)
        {
            return "U" + (userId % 100);
        }
        private static string GetGroupName(int groupId)
        {
            return "G" + (groupId % 100);
        }

    }
}
