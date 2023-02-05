using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Data;
using SenseNet.Security.Messaging.SecurityMessages;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class DependencyTests : TestBase
    {
        /* ================================================================= DEPENDENCY LISTS */

        [TestMethod]
        public void Dependency_Create()
        {
            var parent = new CreateSecurityEntityActivity(2, 0, 1);
            var child = new CreateSecurityEntityActivity(42, 2, 1);
            
            // ACTION
            child.WaitFor(parent);

            // ASSERT
            Assert.IsTrue(parent.WaitingFor.Count == 0);
            Assert.IsTrue(parent.WaitingForMe.Contains(child));
            Assert.IsTrue(child.WaitingFor.Contains(parent));
            Assert.IsTrue(child.WaitingForMe.Count == 0);
        }
        [TestMethod]
        public void Dependency_CreateEntity_Remove()
        {
            var parent = new CreateSecurityEntityActivity(2, 0, 1);
            var child = new CreateSecurityEntityActivity(42, 2, 1);
            child.WaitFor(parent);
            Assert.IsTrue(parent.WaitingFor.Count == 0);
            Assert.IsTrue(parent.WaitingForMe.Contains(child));
            Assert.IsTrue(child.WaitingFor.Contains(parent));
            Assert.IsTrue(child.WaitingForMe.Count == 0);

            // ACTION
            child.FinishWaiting(parent);

            // ASSERT
            Assert.IsTrue(parent.WaitingFor.Count == 0);
            Assert.IsTrue(parent.WaitingForMe.Count == 0);
            Assert.IsTrue(child.WaitingFor.Count == 0);
            Assert.IsTrue(child.WaitingForMe.Count == 0);
        }

        /* ================================================================= CREATE ENTITY */

        [TestMethod]
        public void Dependency_CreateEntity_ParentChild()
        {
            var parent = new CreateSecurityEntityActivity(2, 0, 1);
            var child = new CreateSecurityEntityActivity(42, 2, 1);
            Assert.IsFalse(parent.ShouldWaitFor(child));
            Assert.IsTrue(child.ShouldWaitFor(parent));
        }
        [TestMethod]
        public void Dependency_CreateEntity_Sibling()
        {
            var a1 = new CreateSecurityEntityActivity(43, 40, 1);
            var a2 = new CreateSecurityEntityActivity(42, 40, 1);
            Assert.IsFalse(a1.ShouldWaitFor(a2));
            Assert.IsFalse(a2.ShouldWaitFor(a1));
        }
        [TestMethod]
        public void Dependency_CreateEntity_MembershipActivity()
        {
            var createEntity = new CreateSecurityEntityActivity(42, 40, 1);
            var activities = CreateMembershipActivities();
            foreach (var activity in activities)
            {
                Assert.IsTrue(createEntity.ShouldWaitFor(activity), $"activity is {activity.GetType().Name}");
                Assert.IsTrue(activity.ShouldWaitFor(createEntity), $"activity is {activity.GetType().Name}");
            }
        }
        [TestMethod]
        public void Dependency_CreateEntity_DeleteEntity()
        {
            var context = CreateContext().Security;

            var createEntity = new CreateSecurityEntityActivity(Id("E99"), Id("E8"), 1) { Context = context };

            var deleteEntity = new DeleteSecurityEntityActivity(Id("E8"));
            Assert.IsTrue(createEntity.ShouldWaitFor(deleteEntity));
            deleteEntity = new DeleteSecurityEntityActivity(Id("E3"));
            Assert.IsTrue(createEntity.ShouldWaitFor(deleteEntity));
            deleteEntity = new DeleteSecurityEntityActivity(Id("E21"));
            Assert.IsFalse(createEntity.ShouldWaitFor(deleteEntity));
            deleteEntity = new DeleteSecurityEntityActivity(Id("E31"));
            Assert.IsFalse(createEntity.ShouldWaitFor(deleteEntity));
        }
        [TestMethod]
        public void Dependency_CreateEntity_MoveEntity()
        {
            var createEntity = new CreateSecurityEntityActivity(42, 40, 1);
            var moveEntity = new MoveSecurityEntityActivity(1111, 2222);
            Assert.IsFalse(createEntity.ShouldWaitFor(moveEntity));

            moveEntity = new MoveSecurityEntityActivity(42, 2222);
            Assert.IsTrue(createEntity.ShouldWaitFor(moveEntity));

            moveEntity = new MoveSecurityEntityActivity(1111, 42);
            Assert.IsTrue(createEntity.ShouldWaitFor(moveEntity));
        }
        [TestMethod]
        public void Dependency_CreateEntity_SetAcl()
        {
            var createEntity = new CreateSecurityEntityActivity(42, 40, 1);
            var setAcl = new SetAclActivity();
            Assert.IsFalse(createEntity.ShouldWaitFor(setAcl));
        }

        /* ================================================================= DELETE ENTITY */

        [TestMethod]
        public void Dependency_DeleteEntity_Create()
        {
            var context = CreateContext().Security;

            var deleteEntity = new DeleteSecurityEntityActivity(Id("E8")) {Context = context};

            // Create an entity in the tree to be deleted
            var olderActivity = new CreateSecurityEntityActivity(Id("E99"), Id("E21"), Id("U1"));
            Assert.IsTrue(deleteEntity.ShouldWaitFor(olderActivity));
            // Create an entity NOT in the tree to be deleted
            olderActivity = new CreateSecurityEntityActivity(Id("E99"), Id("E30"), Id("U1"));
            Assert.IsFalse(deleteEntity.ShouldWaitFor(olderActivity));
        }
        [TestMethod]
        public void Dependency_DeleteEntity_Delete()
        {
            var context = CreateContext().Security;

            var deleteEntity = new DeleteSecurityEntityActivity(Id("E8")) { Context = context };

            // Delete an entity from the ancestor chain
            var olderActivity = new DeleteSecurityEntityActivity(Id("E3"));
            Assert.IsTrue(deleteEntity.ShouldWaitFor(olderActivity));
            // Delete an entity NOT from the ancestor chain
            olderActivity = new DeleteSecurityEntityActivity(Id("E4"));
            Assert.IsFalse(deleteEntity.ShouldWaitFor(olderActivity));
        }
        [TestMethod]
        public void Dependency_DeleteEntity_Modify()
        {
            var context = CreateContext().Security;

            var deleteEntity = new DeleteSecurityEntityActivity(Id("E8")) { Context = context };

            // Modify an entity in the tree to be deleted
            var olderActivity = new ModifySecurityEntityOwnerActivity(Id("E21"), Id("U2"));
            Assert.IsTrue(deleteEntity.ShouldWaitFor(olderActivity));
            // Modify an entity NOT in the tree to be deleted
            olderActivity = new ModifySecurityEntityOwnerActivity(Id("E30"), Id("U2"));
            Assert.IsFalse(deleteEntity.ShouldWaitFor(olderActivity));
        }
        [TestMethod]
        public void Dependency_DeleteEntityMove()
        {
            var context = CreateContext().Security;

            var deleteEntity = new DeleteSecurityEntityActivity(Id("E8")) { Context = context };

            // Move an entity from the tree to be deleted
            var olderActivity = new MoveSecurityEntityActivity(Id("E21"), Id("E111"));
            Assert.IsTrue(deleteEntity.ShouldWaitFor(olderActivity));
            // Move an entity to the tree to be deleted
            olderActivity = new MoveSecurityEntityActivity(Id("E50"), Id("E21"));
            Assert.IsTrue(deleteEntity.ShouldWaitFor(olderActivity));
            // Move an entity from the ancestor chain
            olderActivity = new MoveSecurityEntityActivity(Id("E3"), Id("E21"));
            Assert.IsTrue(deleteEntity.ShouldWaitFor(olderActivity));
            // Move an entity NOT from or to the tree to be deleted and NOT from the ancestor chain
            olderActivity = new MoveSecurityEntityActivity(Id("E30"), Id("E111"));
            Assert.IsFalse(deleteEntity.ShouldWaitFor(olderActivity));
        }
        [TestMethod]
        public void Dependency_DeleteEntity_SetAcl()
        {
            var context = CreateContext().Security;

            var deleteEntity = new DeleteSecurityEntityActivity(Id("E8")) { Context = context };

            // Set ACL in the tree to be deleted (E21 in the tree)
            var olderActivity = new SetAclActivity(new[] { new AclInfo(Id("E21")) }, new List<int>(), new List<int>());
            Assert.IsTrue(deleteEntity.ShouldWaitFor(olderActivity));
            olderActivity = new SetAclActivity(new[] { new AclInfo(Id("E30")) }, new List<int> { Id("E21") }, new List<int> { Id("E32") });
            Assert.IsTrue(deleteEntity.ShouldWaitFor(olderActivity));
            olderActivity = new SetAclActivity(new[] { new AclInfo(Id("E30")) }, new List<int> { Id("E31") }, new List<int> { Id("E21") });
            Assert.IsTrue(deleteEntity.ShouldWaitFor(olderActivity));
            // Set ACL NOT in the tree to be deleted
            olderActivity = new SetAclActivity(new[] { new AclInfo(Id("E30")) }, new List<int> { Id("E31") }, new List<int> { Id("E32") });
            Assert.IsFalse(deleteEntity.ShouldWaitFor(olderActivity));
        }

        /* ================================================================= MODIFY ENTITY */

        [TestMethod]
        public void Dependency_ModifyEntity_Create()
        {
            var context = CreateContext().Security;

            var modifyEntity = new ModifySecurityEntityOwnerActivity(Id("E8"), Id("U2")) { Context = context };

            var olderActivity = new CreateSecurityEntityActivity(Id("E8"), Id("E3"), Id("U1"));
            Assert.IsTrue(modifyEntity.ShouldWaitFor(olderActivity));
            olderActivity = new CreateSecurityEntityActivity(Id("E9"), Id("E3"), Id("U1"));
            Assert.IsFalse(modifyEntity.ShouldWaitFor(olderActivity));
        }
        [TestMethod]
        public void Dependency_ModifyEntity_Modify()
        {
            var context = CreateContext().Security;

            var modifyEntity = new ModifySecurityEntityOwnerActivity(Id("E8"), Id("U2")) { Context = context };

            var olderActivity = new ModifySecurityEntityOwnerActivity(Id("E8"), Id("U2"));
            Assert.IsTrue(modifyEntity.ShouldWaitFor(olderActivity));
            olderActivity = new ModifySecurityEntityOwnerActivity(Id("E9"), Id("U2"));
            Assert.IsFalse(modifyEntity.ShouldWaitFor(olderActivity));
        }

        /* ================================================================= MOVE ENTITY */

        [TestMethod]
        public void Dependency_MoveEntity_Create()
        {
            var context = CreateContext().Security;

            var moveEntity = new MoveSecurityEntityActivity(Id("E8"), Id("E9")) { Context = context };

            var olderActivity = new CreateSecurityEntityActivity(Id("E8"), Id("E3"), Id("U1"));
            Assert.IsTrue(moveEntity.ShouldWaitFor(olderActivity));
            olderActivity = new CreateSecurityEntityActivity(Id("E9"), Id("E3"), Id("U1"));
            Assert.IsTrue(moveEntity.ShouldWaitFor(olderActivity));
            olderActivity = new CreateSecurityEntityActivity(Id("E3"), Id("E1"), Id("U1"));
            Assert.IsFalse(moveEntity.ShouldWaitFor(olderActivity));
        }
        [TestMethod]
        public void Dependency_MoveEntity_Delete()
        {
            var context = CreateContext().Security;

            var moveEntity = new MoveSecurityEntityActivity(Id("E8"), Id("E9")) { Context = context };

            var olderActivity = new DeleteSecurityEntityActivity(Id("E8"));
            Assert.IsTrue(moveEntity.ShouldWaitFor(olderActivity));
            olderActivity = new DeleteSecurityEntityActivity(Id("E9"));
            Assert.IsTrue(moveEntity.ShouldWaitFor(olderActivity));
            olderActivity = new DeleteSecurityEntityActivity(Id("E3"));
            Assert.IsTrue(moveEntity.ShouldWaitFor(olderActivity));
            olderActivity = new DeleteSecurityEntityActivity(Id("E10"));
            Assert.IsFalse(moveEntity.ShouldWaitFor(olderActivity));
        }
        [TestMethod]
        public void Dependency_MoveEntity_Move()
        {
            var context = CreateContext().Security;

            var moveEntity = new MoveSecurityEntityActivity(Id("E5"), Id("E6")) { Context = context };

            var olderActivity = new MoveSecurityEntityActivity(Id("E14"), Id("E111"));
            Assert.IsTrue(moveEntity.ShouldWaitFor(olderActivity));
            olderActivity = new MoveSecurityEntityActivity(Id("E111"), Id("E14"));
            Assert.IsTrue(moveEntity.ShouldWaitFor(olderActivity));
            olderActivity = new MoveSecurityEntityActivity(Id("E16"), Id("E111"));
            Assert.IsTrue(moveEntity.ShouldWaitFor(olderActivity));
            olderActivity = new MoveSecurityEntityActivity(Id("E111"), Id("E16"));
            Assert.IsTrue(moveEntity.ShouldWaitFor(olderActivity));
            olderActivity = new MoveSecurityEntityActivity(Id("E111"), Id("E111"));
            Assert.IsFalse(moveEntity.ShouldWaitFor(olderActivity));
        }

        /* ================================================================= SET ACL */

        [TestMethod]
        public void Dependency_SetAcl_Create()
        {
            var context = CreateContext().Security;

            var setAcl = new SetAclActivity(
                new[] {new AclInfo(Id("E30"))},
                new List<int> {Id("E31")},
                new List<int> {Id("E32")}) {Context = context};

            var olderActivity = new CreateSecurityEntityActivity(Id("E30"), Id("E111"), Id("U1"));
            Assert.IsTrue(setAcl.ShouldWaitFor(olderActivity));
            olderActivity = new CreateSecurityEntityActivity(Id("E31"), Id("E111"), Id("U1"));
            Assert.IsTrue(setAcl.ShouldWaitFor(olderActivity));
            olderActivity = new CreateSecurityEntityActivity(Id("E32"), Id("E111"), Id("U1"));
            Assert.IsTrue(setAcl.ShouldWaitFor(olderActivity));
            olderActivity = new CreateSecurityEntityActivity(Id("E33"), Id("E111"), Id("U1"));
            Assert.IsFalse(setAcl.ShouldWaitFor(olderActivity));
        }
        [TestMethod]
        public void Dependency_SetAcl_Delete()
        {
            var context = CreateContext().Security;

            var setAcl = new SetAclActivity(
                    new[] { new AclInfo(Id("E30")) },
                    new List<int> { Id("E31") },
                    new List<int> { Id("E32") })
                { Context = context };

            var olderActivity = new DeleteSecurityEntityActivity(Id("E12"));
            Assert.IsTrue(setAcl.ShouldWaitFor(olderActivity));
            olderActivity = new DeleteSecurityEntityActivity(Id("E11"));
            Assert.IsFalse(setAcl.ShouldWaitFor(olderActivity));
            olderActivity = new DeleteSecurityEntityActivity(Id("E33"));
            Assert.IsFalse(setAcl.ShouldWaitFor(olderActivity));
            olderActivity = new DeleteSecurityEntityActivity(Id("E35"));
            Assert.IsFalse(setAcl.ShouldWaitFor(olderActivity));
        }
        [TestMethod]
        public void Dependency_SetAcl_SetAcl()
        {
            var context = CreateContext().Security;

            var setAcl = new SetAclActivity(
                    new[] { new AclInfo(Id("E30")) },
                    new List<int> { Id("E31") },
                    new List<int> { Id("E32") })
                { Context = context };

            var olderActivity = new SetAclActivity(
                new[] { new AclInfo(Id("E31")) }, new List<int>(), new List<int>());
            Assert.IsTrue(setAcl.ShouldWaitFor(olderActivity));
            olderActivity = new SetAclActivity(
                new[] { new AclInfo(Id("E111")) }, new List<int> { Id("E30") }, new List<int>());
            Assert.IsTrue(setAcl.ShouldWaitFor(olderActivity));
            olderActivity = new SetAclActivity(
                new[] { new AclInfo(Id("E111")) }, new List<int>(), new List<int> { Id("E32") });
            Assert.IsTrue(setAcl.ShouldWaitFor(olderActivity));
            olderActivity = new SetAclActivity(
                new[] { new AclInfo(Id("E111")) }, new List<int> { Id("E112") }, new List<int> { Id("E113") });
            Assert.IsFalse(setAcl.ShouldWaitFor(olderActivity));
        }

        /* ================================================================= MEMBERSHIP */

        [TestMethod]
        public void Dependency_MembershipActivity_AnyOther()
        {
            var membershipActivities = CreateMembershipActivities();
            var anyActivities = CreateAllActivities();
            foreach (var membershipActivity in membershipActivities)
            foreach (var anyActivity in anyActivities)
            {
                Assert.IsTrue(membershipActivity.ShouldWaitFor(anyActivity),
                    $"activities are {membershipActivity.GetType().Name},  {anyActivity.GetType().Name}");
                Assert.IsTrue(anyActivity.ShouldWaitFor(membershipActivity),
                    $"activities are {anyActivity.GetType().Name},  {membershipActivity.GetType().Name}");
            }
        }

        /* ================================================================= TOOLS */

        SecurityActivity[] CreateMembershipActivities()
        {
            return new SecurityActivity[]
            {
                new AddUserToSecurityGroupsActivity(),
                new RemoveUserFromSecurityGroupsActivity(),
                new AddMembersToGroupActivity(),
                new RemoveMembersFromGroupActivity(),
                new DeleteUserActivity(),
                new DeleteGroupActivity(),
                new DeleteIdentitiesActivity()
            };
        }
        SecurityActivity[] CreateAllActivities()
        {
            return new SecurityActivity[]
            {
                new AddUserToSecurityGroupsActivity(),
                new RemoveUserFromSecurityGroupsActivity(),
                new AddMembersToGroupActivity(),
                new RemoveMembersFromGroupActivity(),
                new DeleteUserActivity(),
                new DeleteGroupActivity(),
                new DeleteIdentitiesActivity(),
                new CreateSecurityEntityActivity(),
                new DeleteSecurityEntityActivity(),
                new ModifySecurityEntityOwnerActivity(),
                new MoveSecurityEntityActivity(),
                new SetAclActivity(),
            };
        }

        private Context CreateContext()
        {
            //---- Ensure test data
            var entities = SystemStartTests.CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            //var memberships = Tools.CreateInMemoryMembershipTable("G1:U1,U2|G2:U3,U4|G3:U1,U3|G4:U4|G5:U5");
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = SystemStartTests.CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities };

            //---- Start the system
            var securitySystem = Context.StartTheSystem(new MemoryDataProvider(storage), DiTools.CreateDefaultMessageProvider());

            //---- Start the request
            return new Context(TestUser.User1, securitySystem);

        }

        private int Id(string name) => GetId(name);
    }
}
