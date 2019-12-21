using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;
using System.Collections.Generic;
using System.Linq;
using System.Text;
// ReSharper disable InconsistentNaming
// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable UnusedMember.Local

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class MembershipTests2
    {
        #region G1-G23: initial groups (well known when any test starting)

        private int G1 = Id("G1");
        private int G2 = Id("G2");
        private int G3 = Id("G3");
        private int G4 = Id("G4");
        private int G5 = Id("G5");
        private int G6 = Id("G6");
        private int G7 = Id("G7");
        private int G8 = Id("G8");
        private int G9 = Id("G9");
        private int G10 = Id("G10");
        private int G11 = Id("G11");
        private int G12 = Id("G12");
        private int G13 = Id("G13");
        private int G14 = Id("G14");
        private int G15 = Id("G15");
        private int G16 = Id("G16");
        private int G17 = Id("G17");
        private int G18 = Id("G18");
        private int G19 = Id("G19");
        private int G20 = Id("G20");
        private int G21 = Id("G21");
        private int G22 = Id("G22");
        private int G23 = Id("G23");
        #endregion
        #region G30-G39: additional groups (for any test purposes)

        private int G30 = Id("G30");
        private int G31 = Id("G31");
        private int G32 = Id("G32");
        private int G33 = Id("G33");
        private int G34 = Id("G34");
        private int G35 = Id("G35");
        private int G36 = Id("G36");
        private int G37 = Id("G37");
        private int G38 = Id("G38");
        private int G39 = Id("G39");
        #endregion
        #region U1-U38: initial users (well known when any test starting)

        private int U1 = Id("U1");
        private int U2 = Id("U2");
        private int U3 = Id("U3");
        private int U4 = Id("U4");
        private int U5 = Id("U5");
        private int U6 = Id("U6");
        private int U7 = Id("U7");
        private int U8 = Id("U8");
        private int U9 = Id("U9");
        private int U10 = Id("U10");
        private int U11 = Id("U11");
        private int U12 = Id("U12");
        private int U13 = Id("U13");
        private int U14 = Id("U14");
        private int U15 = Id("U15");
        private int U16 = Id("U16");
        private int U17 = Id("U17");
        private int U18 = Id("U18");
        private int U19 = Id("U19");
        private int U20 = Id("U20");
        private int U21 = Id("U21");
        private int U22 = Id("U22");
        private int U23 = Id("U23");
        private int U24 = Id("U24");
        private int U25 = Id("U25");
        private int U26 = Id("U26");
        private int U27 = Id("U27");
        private int U28 = Id("U28");
        private int U29 = Id("U29");
        private int U30 = Id("U30");
        private int U31 = Id("U31");
        private int U32 = Id("U32");
        private int U33 = Id("U33");
        private int U34 = Id("U34");
        private int U35 = Id("U35");
        private int U36 = Id("U36");
        private int U37 = Id("U37");
        private int U38 = Id("U38");
        #endregion
        #region U40-U49: additional users (for any test purposes)

        private int U40 = Id("U40");
        private int U41 = Id("U41");
        private int U42 = Id("U42");
        private int U43 = Id("U43");
        private int U44 = Id("U44");
        private int U45 = Id("U45");
        private int U46 = Id("U46");
        private int U47 = Id("U47");
        private int U48 = Id("U48");
        private int U49 = Id("U49");
        #endregion
        #region initial membership
        // ReSharper disable once ConvertToConstant.Local
        private readonly string InitialMembership = "U1:G1,G2|U2:G1,G2|U3:G1,G4|U4:G1,G4|U5:G1,G4|U6:G1,G6|U7:G1,G3,G8|U8:G1,G3,G8|U9:G1,G3,G8|U10:G1,G3|" +
                "U11:G1,G3,G10|U12:G1,G3,G11|U13:G1,G3,G11|U14:G1,G5,G12|U15:G1,G5,G12|U16:G1,G5,G12|U17:G1,G5,G12|U18:G1,G5,G12|" +
                "U19:G1,G5,G12|U20:G1,G5,G12|U21:G1,G5,G13|U22:G1,G5,G14|U23:G1,G5,G14|U24:G1,G5,G15|U25:G1,G3,G9,G16|U26:G1,G3,G9,G17|" +
                "U27:G1,G3,G9,G18|U28:G1,G3,G9,G18|U29:G1,G3,G9,G19|U30:G20|U31:G20|U32:G20|U33:G20|U34:G20,G21|U35:G20,G21|U36:G20,G22|" +
                "U37:G20,G23|U38:G20,G23";
        #endregion

        private Context context;
        public TestContext TestContext { get; set; }

        [TestInitialize]
        public void StartTest()
        {
            context = Tools.GetEmptyContext(TestUser.User1);
            Tools.InitializeInMemoryMembershipStorage(@"G1:G2,G3,G4,G5,G6|G2:U1,U2|G3:U10,G7,G8,G9,G10,G11|G4:U3,U4,U5|G5:G12,G13,G14,G15|
                G6:U6|G7:|G8:U7,U8,U9|G9:G16,G17,G18,G19|G10:U11|G11:U12,U13|G12:U14,U15,U16,U17,U18,U19,U20|G13:U21|G14:U22,U23|
                G15:U24|G16:U25|G17:U26|G18:U27,U28|G19:U29|G20:U30,U31,U32,U33,G21,G22,G23|G21:U34,U35|G22:U36|G23:U37,U38");
            context.Security.Cache.Reset(context.Security.DataProvider);
            Assert.AreEqual(InitialMembership, DumpMembership(context.Security));
        }
        [TestCleanup]
        public void Finishtest() //UNDONE:REFACTOR
        {
            Tools.CheckIntegrity(TestContext.TestName, context.Security);
        }

        /*==================================================================================*/

        [TestMethod]
        public void Membership2_MakeCircleWithNewGroup()
        {
            var ctx = context.Security;

            // operation
            ctx.AddMembersToSecurityGroup(G30, null, new[] { G9 }, new[] { G18 });

            // test
            var expected = new MembershipEditor(InitialMembership)
                .AddGroupsToUser(U25, G18, G30)
                .AddGroupsToUser(U26, G18, G30)
                .AddGroupsToUser(U27, G18, G30)
                .AddGroupsToUser(U28, G18, G30)
                .AddGroupsToUser(U29, G18, G30)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_MakeCircleWithNewGroupAndUsers()
        {
            var ctx = context.Security;

            // operation
            ctx.AddMembersToSecurityGroup(G30, new[] { U1, U40 }, new[] { G9 }, new[] { G18 });

            // test
            var expected = new MembershipEditor(InitialMembership)
                .AddGroupsToUser(U1, G3, G9, G18, G30)
                .AddGroupsToUser(U25, G18, G30)
                .AddGroupsToUser(U26, G18, G30)
                .AddGroupsToUser(U27, G18, G30)
                .AddGroupsToUser(U28, G18, G30)
                .AddGroupsToUser(U29, G18, G30)
                .AddGroupsToUser(U40, G1, G3, G9, G18, G30)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_AddExistingUserToMorethanOneGroup() //UNDONE:REFACTOR
        {
            var ctx = context.Security;

            // operation
            ctx.AddUserToSecurityGroups(U1, new[] { G4, G7, G10, G20, G22 });

            // test
            var expected = new MembershipEditor(InitialMembership)
                .AddGroupsToUser(U1, G3, G4, G7, G10, G20, G22)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_AddNewUserToMorethanOneGroup() //UNDONE:REFACTOR
        {
            var ctx = context.Security;

            // operation
            ctx.AddUserToSecurityGroups(U40, new[] { G4, G7, G10, G20, G22 });

            // test
            var expected = new MembershipEditor(InitialMembership)
                .AddGroupsToUser(U40, G1, G3, G4, G7, G10, G20, G22)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_RemoveUserFromMorethanOneGroup() //UNDONE:REFACTOR
        {
            var ctx = context.Security;
            ctx.AddUserToSecurityGroups(U1, new[] { G4, G7, G10, G20, G22 });
            var expected = new MembershipEditor(InitialMembership)
                .AddGroupsToUser(U1, G3, G4, G7, G10, G20, G22)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));

            // operation
            ctx.RemoveUserFromSecurityGroups(U1, new[] { G4, G7, G10, G20, G22 });

            // test
            Assert.AreEqual(InitialMembership, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_AddNewUserToEmptyGroup()
        {
            var ctx = context.Security;

            // operation
            ctx.AddUsersToSecurityGroup(G7, new[] { U40 });

            // test
            var expected = new MembershipEditor(InitialMembership)
                .AddGroupsToUser(U40, G1, G3, G7)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_DeleteGroupFromCircle()
        {
            var ctx = context.Security;

            // preparation (make circle with a new group and an existing and a new user).
            ctx.AddMembersToSecurityGroup(G30, new[] { U1, U40 }, new[] { G9 }, new[] { G18 });
            Assert.AreEqual("U1:G1,G2,G3,G9,G18,G30|U2:G1,G2|U3:G1,G4|U4:G1,G4|U5:G1,G4|U6:G1,G6|U7:G1,G3,G8|U8:G1,G3,G8|U9:G1,G3,G8|U10:G1,G3|" +
                "U11:G1,G3,G10|U12:G1,G3,G11|U13:G1,G3,G11|U14:G1,G5,G12|U15:G1,G5,G12|U16:G1,G5,G12|U17:G1,G5,G12|U18:G1,G5,G12|" +
                "U19:G1,G5,G12|U20:G1,G5,G12|U21:G1,G5,G13|U22:G1,G5,G14|U23:G1,G5,G14|U24:G1,G5,G15|U25:G1,G3,G9,G16,G18,G30|U26:G1,G3,G9,G17,G18,G30|" +
                "U27:G1,G3,G9,G18,G30|U28:G1,G3,G9,G18,G30|U29:G1,G3,G9,G18,G19,G30|U30:G20|U31:G20|U32:G20|U33:G20|U34:G20,G21|U35:G20,G21|U36:G20,G22|" +
                "U37:G20,G23|U38:G20,G23|U40:G1,G3,G9,G18,G30", DumpMembership(ctx));

            // operation
            ctx.DeleteSecurityGroup(G30);

            // test
            Assert.AreEqual(InitialMembership, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_DeleteGroup_RootNode()
        {
            var ctx = context.Security;

            // operation
            ctx.DeleteSecurityGroup(G20);

            // test
            var expected = new MembershipEditor(InitialMembership)
                .DeleteUsers(U30, U31, U32, U33)
                .RemoveGroupsFromUser(U34, G20)
                .RemoveGroupsFromUser(U35, G20)
                .RemoveGroupsFromUser(U36, G20)
                .RemoveGroupsFromUser(U37, G20)
                .RemoveGroupsFromUser(U38, G20)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_DeleteGroup_TreeNode()
        {
            var ctx = context.Security;

            // operation
            ctx.DeleteSecurityGroup(G3);

            // test
            var expected = new MembershipEditor(InitialMembership)
                .DeleteUsers(U10)
                .RemoveGroupsFromUser(U7, G1, G3)
                .RemoveGroupsFromUser(U8, G1, G3)
                .RemoveGroupsFromUser(U9, G1, G3)
                .RemoveGroupsFromUser(U11, G1, G3)
                .RemoveGroupsFromUser(U12, G1, G3)
                .RemoveGroupsFromUser(U13, G1, G3)
                .RemoveGroupsFromUser(U25, G1, G3)
                .RemoveGroupsFromUser(U26, G1, G3)
                .RemoveGroupsFromUser(U27, G1, G3)
                .RemoveGroupsFromUser(U28, G1, G3)
                .RemoveGroupsFromUser(U29, G1, G3)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_DeleteGroup_Leaf()
        {
            var ctx = context.Security;

            // operation
            ctx.DeleteSecurityGroup(G8);

            // test
            var expected = new MembershipEditor(InitialMembership)
                .DeleteUsers(U7, U8, U9)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_RemoveUsersAndGroupsFromRoot()
        {
            var ctx = context.Security;

            // operation
            ctx.RemoveMembersFromSecurityGroup(G20, new[] { U31, U33 }, new[] { G21 });

            // test
            var expected = new MembershipEditor(InitialMembership)
            .DeleteUsers(U31, U33)
            .RemoveGroupsFromUser(U34, G20)
            .RemoveGroupsFromUser(U35, G20)
            .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_RemoveUsersAndGroups()
        {
            var ctx = context.Security;

            // operation
            ctx.RemoveMembersFromSecurityGroup(G3, new[] { U10 }, new[] { G9 }, new[] { G1 });

            // test
            var expected = new MembershipEditor(InitialMembership)
                .DeleteUsers(U10)
                .RemoveGroupFromUsers(G1, U7, U8, U9, U11, U12, U13, U25, U26, U27, U28, U29)
                .RemoveGroupFromUsers(G3, U25, U26, U27, U28, U29)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_DeleteUser()
        {
            var ctx = context.Security;

            // operation
            ctx.DeleteUser(U1);

            // test
            var expected = new MembershipEditor(InitialMembership)
                .DeleteUsers(U1)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_DeleteUser_MoreInstance()
        {
            var ctx = context.Security;
            ctx.AddUserToSecurityGroups(U1, new[] { G4, G7, G10, G20, G22 });
            var expected = new MembershipEditor(InitialMembership)
                .AddGroupsToUser(U1, G3, G4, G7, G10, G20, G22)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));

            // operation
            ctx.DeleteUser(U1);

            // test
            expected = new MembershipEditor(InitialMembership)
                .DeleteUsers(U1)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }


        [TestMethod]
        public void Membership2_DeleteUsersAndGroups()
        {
            var ctx = context.Security;

            // operation
            ctx.DeleteIdentities(new[] { U1, G10, G20, U26 });

            // test
            var expected = new MembershipEditor(InitialMembership)
                .DeleteUsers(U1, U11, U26, U30, U31, U32, U33)
                .RemoveGroupFromUsers(G20, U34, U35, U36, U37, U38)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }


        [TestMethod]
        public void Membership2_DeleteGroup_Complex()
        {
            var ctx = context.Security;

            // preparation
            ctx.AddUserToSecurityGroups(U1, new[] { G5, G18, G20, G23 });
            ctx.AddUserToSecurityGroups(U40, new[] { G20 });
            ctx.AddMembersToSecurityGroup(G20, null, null, new[] { G10, G12 });
            var membershipBefore = DumpMembership(ctx);

            // operation
            ctx.DeleteSecurityGroup(G20);

            // test
            var expected = new MembershipEditor(membershipBefore)
                .RemoveGroupsFromUser(U1, G10, G12, G20)
                .RemoveGroupsFromUser(U34, G1, G3, G5, G10, G12, G20)
                .RemoveGroupsFromUser(U35, G1, G3, G5, G10, G12, G20)
                .RemoveGroupsFromUser(U36, G1, G3, G5, G10, G12, G20)
                .RemoveGroupsFromUser(U37, G1, G3, G5, G10, G12, G20)
                .RemoveGroupsFromUser(U38, G1, G3, G5, G10, G12, G20)
                .DeleteUsers(U30, U31, U32, U33, U40)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_RemoveGroupMember_Complex()
        {
            var ctx = context.Security;

            // preparation
            ctx.AddUserToSecurityGroups(U1, new[] { G5, G18, G20, G23 });
            ctx.AddUserToSecurityGroups(U40, new[] { G20 });
            ctx.AddMembersToSecurityGroup(G20, null, null, new[] { G10, G12 });
            var membershipBefore = DumpMembership(ctx);

            // operation
            ctx.RemoveMembersFromSecurityGroup(G20, null, null, new[] { G10, G12 });

            // test
            var expected = new MembershipEditor(membershipBefore)
                .RemoveGroupsFromUser(U1, G10, G12)
                .RemoveGroupsFromUser(U30, G1, G3, G5, G10, G12)
                .RemoveGroupsFromUser(U31, G1, G3, G5, G10, G12)
                .RemoveGroupsFromUser(U32, G1, G3, G5, G10, G12)
                .RemoveGroupsFromUser(U33, G1, G3, G5, G10, G12)
                .RemoveGroupsFromUser(U34, G1, G3, G5, G10, G12)
                .RemoveGroupsFromUser(U35, G1, G3, G5, G10, G12)
                .RemoveGroupsFromUser(U36, G1, G3, G5, G10, G12)
                .RemoveGroupsFromUser(U37, G1, G3, G5, G10, G12)
                .RemoveGroupsFromUser(U38, G1, G3, G5, G10, G12)
                .RemoveGroupsFromUser(U40, G1, G3, G5, G10, G12)
                .ToString();
            Assert.AreEqual(expected, DumpMembership(ctx));
        }

        [TestMethod]
        public void Membership2_IsInGroup()
        {
            var ctx = context.Security;

            // user in group
            Assert.IsTrue(ctx.IsInGroup(U13, G11)); // direct parent
            Assert.IsTrue(ctx.IsInGroup(U13, G3));  // parent of parent (transitive)
            Assert.IsFalse(ctx.IsInGroup(U13, G4)); // unrelated

            // group in group
            Assert.IsTrue(ctx.IsInGroup(G11, G3));  // direct parent
            Assert.IsTrue(ctx.IsInGroup(G11, G1));  // parent of parent (transitive)
            Assert.IsFalse(ctx.IsInGroup(G11, G4)); // unrelated

            ctx.DeleteSecurityGroup(G3);

            // user in group
            Assert.IsTrue(ctx.IsInGroup(U13, G11)); // direct parent
            Assert.IsFalse(ctx.IsInGroup(U13, G3)); // parent of parent (transitive)
            Assert.IsFalse(ctx.IsInGroup(U13, G4)); // unrelated

            // group in group
            Assert.IsFalse(ctx.IsInGroup(G11, G3)); // direct parent
            Assert.IsFalse(ctx.IsInGroup(G11, G1)); // parent of parent (transitive)
            Assert.IsFalse(ctx.IsInGroup(G11, G4)); // unrelated
        }

        [TestMethod]
        public void Membership2_IsInGroup_Self()
        {
            var ctx = context.Security;

            // not a member of itself
            Assert.IsFalse(ctx.IsInGroup(U13, U13)); // user in user
            Assert.IsFalse(ctx.IsInGroup(G3, G3));   // group in itself
        }

        /*==================================================================================*/

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

        private static int Id(string name)
        {
            return Tools.GetId(name);
        }

        private class MembershipEditor
        {
            private Dictionary<int, List<int>> Membership = new Dictionary<int, List<int>>();

            public MembershipEditor(string initialState)
            {
                foreach (var userRecord in initialState.Split('|'))
                {
                    var s = userRecord.Split(':');
                    var userId = Id(s[0]);
                    Membership[userId] = s[1].Split(',').Select(Id).ToList();
                }
            }

            public override string ToString()
            {
                return DumpMembership(Membership);
            }

            //-------------------------------------------------------------------------------------

            public MembershipEditor AddGroupsToUser(int userId, params int[] groupIds)
            {
                if (!Membership.TryGetValue(userId, out var user))
                {
                    Membership[userId] = groupIds.Distinct().ToList();
                }
                else
                {
                    foreach (var groupId in groupIds)
                        if (!user.Contains(groupId))
                            user.Add(groupId);
                }
                return this;
            }

            internal MembershipEditor DeleteUsers(params int[] userIds)
            {
                foreach (var userId in userIds)
                    Membership.Remove(userId);
                return this;
            }

            internal MembershipEditor RemoveGroupsFromUser(int userId, params int[] groupIds)
            {
                if (Membership.TryGetValue(userId, out var user))
                    user.RemoveAll(groupIds.Contains);
                return this;
            }

            internal MembershipEditor RemoveGroupFromUsers(int groupId, params int[] userIds)
            {
                foreach (var userId in userIds)
                    RemoveGroupsFromUser(userId, groupId);
                return this;
            }
        }
    }
}
