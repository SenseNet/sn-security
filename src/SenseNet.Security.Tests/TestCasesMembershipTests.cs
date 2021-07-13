using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    public abstract partial class TestCases
    {
        private DataHandler DataHandler => SecuritySystem.Instance.DataHandler;

        [TestMethod]
        public void Membership_StoreSimpleGroup()
        {
            const int groupId = 101;
            //var group = new TestGroup { Id = groupId, };
            //group.SetGroupMembers(new TestGroup[0]);
            //group.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 });
            //group.SetGroupsWhereThisIsMember(new TestGroup[0]);

            //# storing a new totally completed group.
            CurrentContext.Security.DeleteSecurityGroup(101);
            CurrentContext.Security.AddMembersToSecurityGroup(101, new[] { TestUser.User1.Id, TestUser.User2.Id }, new int[0], new int[0]);

            var loaded = DataHandler.GetSecurityGroup(groupId);
            Assert.AreEqual(groupId, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            Assert.AreEqual("U1:G1|U2:G1", DumpMembership(CurrentContext.Security));
        }
        [TestMethod]
        public void Membership_StoreTwoGroups()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 });
            group1.SetGroupMembers(new[] { group2 });
            group2.SetGroupMembers(new TestGroup[0]);
            group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetGroupsWhereThisIsMember(new[] { group1 });

            //# storing a new totally completed group.
            CurrentContext.Security.DeleteSecurityGroup(101);
            CurrentContext.Security.AddMembersToSecurityGroup(101, new[] { TestUser.User1.Id, TestUser.User2.Id }, new[] { 102 }, new int[0]);
            CurrentContext.Security.DeleteSecurityGroup(102);
            CurrentContext.Security.AddMembersToSecurityGroup(102, new[] { TestUser.User3.Id, TestUser.User4.Id }, new int[0], new[] { 101 });

            // check
            Assert.AreEqual("U1:G1|U2:G1|U3:G1,G2|U4:G1,G2", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void Membership_StoreGroupCircle()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User5 }); group3.SetGroupMembers(new[] { group1 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });


            //# storing a new totally completed group.
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G1,G2,G3|U5:G1,G2,G3", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User5.Id));
        }


        [TestMethod]
        public void Membership_DeleteRootGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            //# deleting a group that is has member but it is not member of another one.
            CurrentContext.Security.DeleteSecurityGroup(groupId1);

            // check
            Assert.AreEqual("U3:G2|U4:G2", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.IsNull(loaded);

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void Membership_DeleteMemberGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            //# deleting a group that is member of another one
            group1.RemoveGroup(group2);
            CurrentContext.Security.DeleteSecurityGroup(group2.Id);

            // check
            Assert.AreEqual("U1:G1|U2:G1", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.IsNull(loaded);
        }
        [TestMethod]
        public void Membership_DeleteMemberGroupById()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            //# deleting a group that is member of another one
            group1.RemoveGroup(group2);
            CurrentContext.Security.DeleteSecurityGroup(group2.Id);
            // update group that contained the removed group
            //CurrentContext.Security.AddOrModifySecurityGroup(groupId1, new[] { TestUser.User1.Id, TestUser.User2.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.IsNull(loaded);
        }
        [TestMethod]
        public void Membership_DeleteGroupFromCircle()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User3, TestUser.User5 }); group3.SetGroupMembers(new[] { group1 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });

            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);

            //# deleting a group that is an item of a circle
            group2.RemoveGroup(group3);
            CurrentContext.Security.DeleteSecurityGroup(group3.Id);


            // check
            Assert.AreEqual("U1:G1|U2:G1|U3:G1,G2|U4:G1,G2", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.IsNull(loaded);
        }
        [TestMethod]
        public void Membership_DeleteUnknownGroup()
        {

            //# deleting an unknown group
            CurrentContext.Security.DeleteSecurityGroup(int.MaxValue);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Membership_DeleteInvalidGroup()
        {

            //# deleting an invalid group
            CurrentContext.Security.DeleteSecurityGroup(default);

        }


        [TestMethod]
        public void Membership_AddUserToRootGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            //# Adding user and registering the change.
            group1.AddUser(TestUser.User3);
            CurrentContext.Security.AddUsersToSecurityGroup(group1.Id, new[] { TestUser.User3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));
        }
        [TestMethod]
        public void Membership_AddUserToMemberGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            //# Adding user and registering the change.
            group2.AddUser(TestUser.User3);
            CurrentContext.Security.AddUsersToSecurityGroup(group2.Id, new[] { TestUser.User3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G2", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void Membership_AddUserToGroupInCircle()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User5 }); group3.SetGroupMembers(new[] { group1 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });

            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);

            //# Adding user and registering the change.
            group1.AddUser(TestUser.User6);
            CurrentContext.Security.AddUsersToSecurityGroup(group1.Id, new[] { TestUser.User6.Id });


            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G1,G2,G3|U5:G1,G2,G3|U6:G1,G2,G3", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(3, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User6.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User5.Id));
        }

        [TestMethod]
        public void Membership_RemoveUserFromRootGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            //# Removing user and registering the change.
            group1.RemoveUser(TestUser.User2);
            CurrentContext.Security.RemoveUsersFromSecurityGroup(group1.Id, new[] { TestUser.User2.Id });

            // check
            Assert.AreEqual("U1:G1|U3:G1,G2|U4:G1,G2", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void Membership_RemoveUserFromMemberGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            //# Removing user and registering the change.
            group2.RemoveUser(TestUser.User4);
            CurrentContext.Security.RemoveUsersFromSecurityGroup(group2.Id, new[] { TestUser.User4.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1|U3:G1,G2", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void Membership_RemoveUserFromGroupInCircle()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1, TestUser.User2 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User3, TestUser.User4 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User5 }); group3.SetGroupMembers(new[] { group1 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });

            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);

            //# Removing user and registering the change.
            group1.RemoveUser(TestUser.User2);
            CurrentContext.Security.RemoveUsersFromSecurityGroup(group1.Id, new[] { TestUser.User2.Id });

            // check
            Assert.AreEqual("U1:G1,G2,G3|U3:G1,G2,G3|U4:G1,G2,G3|U5:G1,G2,G3", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(2, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User5.Id));
        }


        [TestMethod]
        public void Membership_AddGroupToRootGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            const int groupId3 = 103;
            var group3 = new TestGroup { Id = groupId3 };
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new TestGroup[0]); group3.SetGroupsWhereThisIsMember(new TestGroup[0]);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);

            //# Adding group and registering the change.
            group1.SetGroupMembers(new[] { group2, group3 });
            group3.SetGroupsWhereThisIsMember(new[] { group1 }); // necessary only in test
            CurrentContext.Security.AddGroupsToSecurityGroup(group1.Id, new[] { group2.Id, group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G3", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void Membership_AddGroupToMemberGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            const int groupId3 = 103;
            var group3 = new TestGroup { Id = groupId3 };
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new TestGroup[0]); group3.SetGroupsWhereThisIsMember(new TestGroup[0]);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);

            //# Adding group and registering the change.
            group2.SetGroupMembers(new[] { group3 });
            group3.SetGroupsWhereThisIsMember(new[] { group2 }); // necessary only in test
            CurrentContext.Security.AddGroupsToSecurityGroup(group2.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G2,G3", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void Membership_AddGroupToGroupInCircle()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
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
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);

            const int groupId4 = 104;
            var group4 = new TestGroup { Id = groupId4 };
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 });
            group4.SetGroupMembers(new TestGroup[0]);
            group4.SetGroupsWhereThisIsMember(new TestGroup[0]);
            AddOrModifySecurityGroup(CurrentContext.Security, group4);

            //# Adding group and registering the change.
            group1.SetGroupMembers(new[] { group2, group4 });
            group4.SetGroupsWhereThisIsMember(new[] { group1 }); // necessary only in test
            CurrentContext.Security.AddGroupsToSecurityGroup(group1.Id, new[] { group2.Id, group4.Id });

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G1,G2,G3,G4", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }

        [TestMethod]
        public void Membership_RemoveGroupFromRootGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2, group3 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new TestGroup[0]); group3.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);

            //# Removing group and registering the change.
            group1.SetGroupMembers(new[] { group2 });
            group3.SetGroupsWhereThisIsMember(new TestGroup[0]); // necessary only in test
            CurrentContext.Security.RemoveGroupsFromSecurityGroup(group1.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G3", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void Membership_RemoveGroupFromMemberGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new TestGroup[0]); group3.SetGroupsWhereThisIsMember(new[] { group2 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);

            //# Removing group and registering the change.
            group2.SetGroupMembers(new TestGroup[0]);
            group3.SetGroupsWhereThisIsMember(new TestGroup[0]); // necessary only in test
            CurrentContext.Security.RemoveGroupsFromSecurityGroup(group2.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G3", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));
        }
        [TestMethod]
        public void Membership_RemoveGroupFromGroupInCircle()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            const int groupId4 = 104;
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
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);
            AddOrModifySecurityGroup(CurrentContext.Security, group4);

            //# Removing group and registering the change.
            group1.RemoveGroup(group4);
            CurrentContext.Security.RemoveGroupsFromSecurityGroup(group1.Id, new[] { group4.Id });

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G4", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }

        [TestMethod]
        public void Membership_AddGroupChainToRootGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            const int groupId3 = 103;
            const int groupId4 = 104;
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new[] { group4 }); group3.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 }); group4.SetGroupMembers(new TestGroup[0]); group4.SetGroupsWhereThisIsMember(new[] { group3 });
            AddOrModifySecurityGroup(CurrentContext.Security, group3);
            AddOrModifySecurityGroup(CurrentContext.Security, group4);

            //# Adding group chain and registering the change.
            group1.SetGroupMembers(new[] { group2, group3 });
            group3.SetGroupsWhereThisIsMember(new[] { group1 }); // necessary only in test
            CurrentContext.Security.AddGroupsToSecurityGroup(group1.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G3|U4:G1,G3,G4", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void Membership_AddGroupChainToMemberGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);

            const int groupId3 = 103;
            const int groupId4 = 104;
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new[] { group4 }); group3.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 }); group4.SetGroupMembers(new TestGroup[0]); group4.SetGroupsWhereThisIsMember(new[] { group3 });
            AddOrModifySecurityGroup(CurrentContext.Security, group3);
            AddOrModifySecurityGroup(CurrentContext.Security, group4);

            //# Adding group chain and registering the change.
            group2.SetGroupMembers(new[] { group3 });
            group3.SetGroupsWhereThisIsMember(new[] { group2 }); // necessary only in test
            CurrentContext.Security.AddGroupsToSecurityGroup(group2.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G2,G3|U4:G1,G2,G3,G4", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void Membership_AddGroupChainToGroupInCircle()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new[] { group3 });
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new[] { group1 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });

            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);

            const int groupId4 = 104;
            const int groupId5 = 105;
            var group4 = new TestGroup { Id = groupId4 };
            var group5 = new TestGroup { Id = groupId5 };
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 }); group4.SetGroupMembers(new[] { group5 }); group4.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group5.SetUserMembers(new ISecurityUser[] { TestUser.User5 }); group5.SetGroupMembers(new TestGroup[0]); group4.SetGroupsWhereThisIsMember(new[] { group4 });
            AddOrModifySecurityGroup(CurrentContext.Security, group4);
            AddOrModifySecurityGroup(CurrentContext.Security, group5);

            //# Adding group and registering the change.
            group1.SetGroupMembers(new[] { group2, group4 });
            group4.SetGroupsWhereThisIsMember(new[] { group1 }); // necessary only in test
            CurrentContext.Security.AddGroupsToSecurityGroup(group1.Id, new[] { group4.Id });

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G1,G2,G3,G4|U5:G1,G2,G3,G4,G5", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(groupId5);
            Assert.AreEqual(groupId5, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User5.Id));
        }

        [TestMethod]
        public void Membership_RemoveGroupChainFromRootGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            const int groupId4 = 104;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2, group3 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new TestGroup[0]); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new[] { group4 }); group3.SetGroupsWhereThisIsMember(new[] { group1 });
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 }); group4.SetGroupMembers(new TestGroup[0]); group4.SetGroupsWhereThisIsMember(new[] { group3 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);
            AddOrModifySecurityGroup(CurrentContext.Security, group4);

            //# Removing group and registering the change.
            group1.SetGroupMembers(new[] { group2 });
            group3.SetGroupsWhereThisIsMember(new TestGroup[0]); // necessary only in test
            CurrentContext.Security.RemoveGroupsFromSecurityGroup(group1.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G3|U4:G3,G4", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void Membership_RemoveGroupChainFromMemberGroup()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            const int groupId4 = 104;
            var group1 = new TestGroup { Id = groupId1 };
            var group2 = new TestGroup { Id = groupId2 };
            var group3 = new TestGroup { Id = groupId3 };
            var group4 = new TestGroup { Id = groupId4 };
            group1.SetUserMembers(new ISecurityUser[] { TestUser.User1 }); group1.SetGroupMembers(new[] { group2 }); group1.SetGroupsWhereThisIsMember(new TestGroup[0]);
            group2.SetUserMembers(new ISecurityUser[] { TestUser.User2 }); group2.SetGroupMembers(new[] { group3 }); group2.SetGroupsWhereThisIsMember(new[] { group1 });
            group3.SetUserMembers(new ISecurityUser[] { TestUser.User3 }); group3.SetGroupMembers(new[] { group4 }); group3.SetGroupsWhereThisIsMember(new[] { group2 });
            group4.SetUserMembers(new ISecurityUser[] { TestUser.User4 }); group4.SetGroupMembers(new TestGroup[0]); group3.SetGroupsWhereThisIsMember(new[] { group3 });
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);
            AddOrModifySecurityGroup(CurrentContext.Security, group4);

            //# Removing group and registering the change.
            group2.SetGroupMembers(new TestGroup[0]);
            group3.SetGroupsWhereThisIsMember(new TestGroup[0]); // necessary only in test
            CurrentContext.Security.RemoveGroupsFromSecurityGroup(group2.Id, new[] { group3.Id });

            // check
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G3|U4:G3,G4", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));
        }
        [TestMethod]
        public void Membership_RemoveGroupChainFromGroupInCircle()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            const int groupId4 = 104;
            const int groupId5 = 105;
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
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);
            AddOrModifySecurityGroup(CurrentContext.Security, group4);
            AddOrModifySecurityGroup(CurrentContext.Security, group5);

            //# Removing group and registering the change.
            group1.SetGroupMembers(new[] { group2 });
            group4.SetGroupsWhereThisIsMember(new TestGroup[0]);  // necessary only in test
            CurrentContext.Security.RemoveGroupsFromSecurityGroup(group1.Id, new[] { group4.Id });

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G4|U5:G4,G5", DumpMembership(CurrentContext.Security));

            var loaded = DataHandler.GetSecurityGroup(groupId1);
            Assert.AreEqual(groupId1, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User1.Id));

            loaded = DataHandler.GetSecurityGroup(groupId2);
            Assert.AreEqual(groupId2, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User2.Id));

            loaded = DataHandler.GetSecurityGroup(groupId3);
            Assert.AreEqual(groupId3, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User3.Id));

            loaded = DataHandler.GetSecurityGroup(groupId4);
            Assert.AreEqual(groupId4, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User4.Id));

            loaded = DataHandler.GetSecurityGroup(groupId5);
            Assert.AreEqual(groupId5, loaded.Id);
            Assert.AreEqual(1, loaded.UserMemberIds.Count);
            Assert.IsTrue(loaded.UserMemberIds.Contains(TestUser.User5.Id));
        }

        [TestMethod]
        public void Membership_RemoveGroupThatContainsCircle()
        {
            Prepare_GroupThatContainsCircle_Test();
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G2,G3,G4,G5|U4:G1,G2,G3,G4,G5|U5:G1,G2,G3,G4,G5", DumpMembership(CurrentContext.Security));

            //# Removing group and registering the change.
            CurrentContext.Security.RemoveGroupsFromSecurityGroup(Id("G1"), new[] { Id("G2") });

            Assert.AreEqual("U1:G1|U2:G2|U3:G2,G3,G4,G5|U4:G2,G3,G4,G5|U5:G2,G3,G4,G5", DumpMembership(CurrentContext.Security));
        }
        [TestMethod]
        public void Membership_DeleteGroupThatContainsCircle()
        {
            Prepare_GroupThatContainsCircle_Test();
            Assert.AreEqual("U1:G1|U2:G1,G2|U3:G1,G2,G3,G4,G5|U4:G1,G2,G3,G4,G5|U5:G1,G2,G3,G4,G5", DumpMembership(CurrentContext.Security));

            //# Deleting group and registering the change.
            CurrentContext.Security.DeleteSecurityGroup(Id("G2"));

            Assert.AreEqual("U1:G1|U3:G3,G4,G5|U4:G3,G4,G5|U5:G3,G4,G5", DumpMembership(CurrentContext.Security));
        }
        private void Prepare_GroupThatContainsCircle_Test()
        {
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            const int groupId4 = 104;
            const int groupId5 = 105;
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
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);
            AddOrModifySecurityGroup(CurrentContext.Security, group4);
            AddOrModifySecurityGroup(CurrentContext.Security, group5);
        }


        [TestMethod]
        public void Membership_Flattening()
        {
            // make two disjunctive structure
            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            const int groupId4 = 104;
            const int groupId5 = 105;
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
            AddOrModifySecurityGroup(CurrentContext.Security, group1);
            AddOrModifySecurityGroup(CurrentContext.Security, group2);
            AddOrModifySecurityGroup(CurrentContext.Security, group3);
            AddOrModifySecurityGroup(CurrentContext.Security, group4);
            AddOrModifySecurityGroup(CurrentContext.Security, group5);

            // check
            Assert.AreEqual("U1:G1,G2,G3|U2:G1,G2,G3|U3:G1,G2,G3|U4:G4|U5:G4,G5", DumpMembership(CurrentContext.Security));
        }

        [TestMethod]
        public void DynamicMembership_1()
        {
            var savedGroups = TestUser.User1.GetDynamicGroups(int.MaxValue); // for tests only
            try
            {
                EnsureRepository();

                // Test description:
                // U1 and U2 are in the G2, G3.
                // There is a group: G4.
                // In repository (see the SecurityTreeForTests.vsd) the second level nodes belong to a group: E2 - G1, E3 - G2, E4 - G3. For example these are the work-spaces.
                // Every work-space's first node is secret (E5, E8, E11) so these are broken but they have open permission for a group: G4.
                // Let the rule for dynamic group setting is the following:
                //     if the U1 user gets the secret node, she is in the G4 group if she has open permission for the parent workspace.

                CleanupMemberships();

                SetMembership(CurrentContext.Security, "U1:G2,G3");

                SetAcl(CurrentContext.Security, "+E2|Normal|+G1:______________+");
                SetAcl(CurrentContext.Security, "+E3|Normal|+G2:______________+");
                SetAcl(CurrentContext.Security, "+E4|Normal|+G3:______________+");

                SetAcl(CurrentContext.Security, "-E5|Normal|+G4:______________+");
                SetAcl(CurrentContext.Security, "-E8|Normal|+G4:______________+");
                SetAcl(CurrentContext.Security, "-E11|Normal|+G4:______________+");

                //# User hasn't read permission so she is not in the G4 group
                TestUser.User1.SetDynamicGroups(null);
                Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E5"), PermissionType.See));

                //# User has read permission on E3 so she is in the G4 group
                TestUser.User1.SetDynamicGroups(new[] { Id("G4") });
                Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E8"), PermissionType.See));

                //# User has read permission on E4 so she is in the G4 group
                TestUser.User1.SetDynamicGroups(new[] { Id("G4") });
                Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E11"), PermissionType.See));
            }
            finally
            {
                TestUser.User1.SetDynamicGroups(savedGroups);
            }
        }
        [TestMethod]
        public void DynamicMembership_FlattenDynamicGroups()
        {
            var ctx = CurrentContext.Security;

            // #1: Create the identity structure: G1(U1,G2), G2(U2, G3), G3(U3, G1), G4(U4, G5), G5(U5)

            const int groupId1 = 101;
            const int groupId2 = 102;
            const int groupId3 = 103;
            const int groupId4 = 104;
            const int groupId5 = 105;
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
            ed.Allow(entityId, group1.Id, false, PermissionType.Open, PermissionType.Custom01);
            ed.Allow(entityId, group2.Id, false, PermissionType.Open, PermissionType.Custom02);
            ed.Allow(entityId, group3.Id, false, PermissionType.Open, PermissionType.Custom03);
            ed.Allow(entityId, group4.Id, false, PermissionType.Open, PermissionType.Custom04);
            ed.Allow(entityId, group5.Id, false, PermissionType.Open, PermissionType.Custom05);
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


        /* ======================================================================= Tools */

        internal static void AddOrModifySecurityGroup(TestSecurityContext ctx, TestGroup group)
        {
            ctx.AddMembersToSecurityGroup(group.Id, group.GetUserMembers().Select(u => u.Id).ToArray(), group.GetGroupMembers().Select(g => g.Id).ToArray(), group.GetGroupsWhereThisIsMember().Select(p => p.Id).ToArray());
        }

        internal static string DumpMembership(SecurityContext context)
        {
            return DumpMembership(context.Cache.Membership);
        }
        public static string DumpMembership(Dictionary<int, List<int>> membership)
        {
            if (membership.Count == 0)
                return string.Empty;

            var sb = new StringBuilder();
            foreach (var userId in membership.Keys.OrderBy(s => s))
            {
                sb.Append(GetUserName(userId)).Append(":");
                sb.Append(string.Join(",", membership[userId].OrderBy(s => s).Select(GetGroupName)));
                sb.Append("|");
            }
            sb.Length--;
            return sb.ToString();
        }
        private static string GetUserName(int userId)
        {
            return "U" + userId % 100;
        }
        private static string GetGroupName(int groupId)
        {
            return "G" + groupId % 100;
        }

    }
}
