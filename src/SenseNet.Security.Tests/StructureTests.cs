using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security;
using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;
using System.Diagnostics;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class StructureTests
    {
        Context context;
        public TestContext TestContext { get; set; }

        [TestCleanup]
        public void Finishtest()
        {
            Tools.CheckIntegrity(TestContext.TestName, context.Security);
        }

        //===================================================================

        [TestMethod]
        public void Structure_High_CreateRootEntity()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            var id = Id("E101");
            var entity = new TestEntity { Id = id, OwnerId = TestUser.User1.Id, Parent = null };

            //# calling the security component
            context.Security.CreateSecurityEntity(entity);

            var dbEntity = GetStoredSecurityEntity(context, id);
            var memEntity = context.Security.GetSecurityEntity(id);

            Assert.AreEqual(id, dbEntity.Id);
            Assert.AreEqual(id, memEntity.Id);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User1.Id, dbEntity.OwnerId);
            Assert.AreEqual(TestUser.User1.Id, memEntity.OwnerId);
            Assert.IsTrue(dbEntity.IsInherited);
            Assert.IsTrue(memEntity.IsInherited);
        }
        [TestMethod]
        public void Structure_Low_CreateRootEntity()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            var id = Id("E101");

            //# calling the security component for creating one entity
            context.Security.CreateSecurityEntity(id, default(int), TestUser.User1.Id);

            var dbEntity = GetStoredSecurityEntity(context, id);
            var memEntity = context.Security.GetSecurityEntity(id);

            Assert.AreEqual(id, dbEntity.Id);
            Assert.AreEqual(id, memEntity.Id);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User1.Id, dbEntity.OwnerId);
            Assert.AreEqual(TestUser.User1.Id, memEntity.OwnerId);
            Assert.IsTrue(dbEntity.IsInherited);
            Assert.IsTrue(memEntity.IsInherited);
        }
        [TestMethod]
        public void Structure_CreateChildEntityChain()
        {
            // Preparing
            StartTheSystem();
            context = new Context(TestUser.User1);
            var rootId = Id("E101");
            var rootEntity = new TestEntity { Id = rootId, OwnerId = TestUser.User1.Id, Parent = null };
            var childId = Id("E102");
            var childEntity = new TestEntity { Id = childId, OwnerId = TestUser.User2.Id, Parent = rootEntity };
            var grandChildId = Id("E103");
            var grandChildEntity = new TestEntity { Id = grandChildId, OwnerId = TestUser.User3.Id, Parent = childEntity };

            //# calling the security component for creating an entity chain
            context.Security.CreateSecurityEntity(rootEntity);
            context.Security.CreateSecurityEntity(childEntity);
            context.Security.CreateSecurityEntity(grandChildEntity);

            // inspection
            SecurityEntity memEntity;
            StoredSecurityEntity dbEntity;
            memEntity = context.Security.GetSecurityEntity(rootId);
            Assert.AreEqual(0, memEntity.Level);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User1.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(context, rootId);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User1.Id, dbEntity.OwnerId);

            memEntity = context.Security.GetSecurityEntity(childId);
            Assert.AreEqual(1, memEntity.Level);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(context, childId);
            Assert.AreEqual(rootId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);

            memEntity = context.Security.GetSecurityEntity(grandChildId);
            Assert.AreEqual(2, memEntity.Level);
            Assert.AreEqual(childId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User3.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(context, grandChildId);
            Assert.AreEqual(childId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User3.Id, dbEntity.OwnerId);
        }
        [TestMethod]
        public void Structure_CreateChildEntityChainByIds()
        {
            // Preparing
            StartTheSystem();
            context = new Context(TestUser.User1);
            var rootId = Id("E101");
            var childId = Id("E102");
            var grandChildId = Id("E103");

            //# calling the security component for creating an entity chain
            context.Security.CreateSecurityEntity(rootId, default(int), TestUser.User1.Id);
            context.Security.CreateSecurityEntity(childId, rootId, TestUser.User2.Id);
            context.Security.CreateSecurityEntity(grandChildId, childId, TestUser.User3.Id);

            // inspection
            var db = new PrivateObject(context.Security.DataProvider);
            SecurityEntity memEntity;
            StoredSecurityEntity dbEntity;
            memEntity = context.Security.GetSecurityEntity(rootId);
            Assert.AreEqual(0, memEntity.Level);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User1.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(context, rootId);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User1.Id, dbEntity.OwnerId);

            memEntity = context.Security.GetSecurityEntity(childId);
            Assert.AreEqual(1, memEntity.Level);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(context, childId);
            Assert.AreEqual(rootId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);

            memEntity = context.Security.GetSecurityEntity(grandChildId);
            Assert.AreEqual(2, memEntity.Level);
            Assert.AreEqual(childId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User3.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(context, grandChildId);
            Assert.AreEqual(childId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User3.Id, dbEntity.OwnerId);
        }
        [TestMethod]
        public void Structure_EntityLevel()
        {
            // Preparing
            StartTheSystem();
            context = new Context(TestUser.User1);
            var rootId = Id("E101");
            var rootEntity = new TestEntity { Id = rootId, OwnerId = TestUser.User1.Id, Parent = null };
            var childId1 = Id("E102");
            var childEntity1 = new TestEntity { Id = childId1, OwnerId = TestUser.User1.Id, Parent = rootEntity };
            var childId2 = Id("E103");
            var childEntity2 = new TestEntity { Id = childId2, OwnerId = TestUser.User1.Id, Parent = rootEntity };
            var grandChildId1 = Id("E104");
            var grandChildEntity1 = new TestEntity { Id = grandChildId1, OwnerId = TestUser.User1.Id, Parent = childEntity1 };
            var grandChildId2 = Id("E105");
            var grandChildEntity2 = new TestEntity { Id = grandChildId2, OwnerId = TestUser.User1.Id, Parent = childEntity1 };
            var grandChildId3 = Id("E106");
            var grandChildEntity3 = new TestEntity { Id = grandChildId3, OwnerId = TestUser.User1.Id, Parent = childEntity2 };

            //# calling the security component for structure creation
            context.Security.CreateSecurityEntity(rootEntity);
            context.Security.CreateSecurityEntity(childEntity1);
            context.Security.CreateSecurityEntity(childEntity2);
            context.Security.CreateSecurityEntity(grandChildEntity1);
            context.Security.CreateSecurityEntity(grandChildEntity2);
            context.Security.CreateSecurityEntity(grandChildEntity3);

            // checking target object structure in memory
            SecurityEntity entity;
            entity = context.Security.GetSecurityEntity(rootId);
            Assert.AreEqual(0, entity.Level);
            entity = context.Security.GetSecurityEntity(childId1);
            Assert.AreEqual(1, entity.Level);
            entity = context.Security.GetSecurityEntity(childId2);
            Assert.AreEqual(1, entity.Level);
            entity = context.Security.GetSecurityEntity(grandChildId1);
            Assert.AreEqual(2, entity.Level);
            entity = context.Security.GetSecurityEntity(grandChildId2);
            Assert.AreEqual(2, entity.Level);
            entity = context.Security.GetSecurityEntity(grandChildId3);
            Assert.AreEqual(2, entity.Level);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Structure_CreateSecurityEntity_invalidId()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            //# calling the security component
            context.Security.CreateSecurityEntity(default(int), default(int), default(int));
        }
        [TestMethod]
        public void Structure_CreateSecurityEntity_existing()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, Parent = null };
            context.Security.CreateSecurityEntity(entity);
            entity.OwnerId = TestUser.User2.Id;
            context.Security.CreateSecurityEntity(entity);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void Structure_CreateSecurityEntity_missingParent()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, ParentId = int.MaxValue };
            context.Security.CreateSecurityEntity(entity);
        }



        [TestMethod]
        public void Structure_High_DeleteEntity()
        {
            // Preparing
            StartTheSystem();
            context = new Context(TestUser.User1);
            var rootId = Id("E101");
            var rootEntity = new TestEntity { Id = rootId, OwnerId = TestUser.User1.Id, Parent = null };
            var childId1 = Id("E102");
            var childEntity1 = new TestEntity { Id = childId1, OwnerId = TestUser.User1.Id, Parent = rootEntity };
            var childId2 = Id("E103");
            var childEntity2 = new TestEntity { Id = childId2, OwnerId = TestUser.User1.Id, Parent = rootEntity };
            var grandChildId1 = Id("E104");
            var grandChildEntity1 = new TestEntity { Id = grandChildId1, OwnerId = TestUser.User1.Id, Parent = childEntity1 };
            var grandChildId2 = Id("E105");
            var grandChildEntity2 = new TestEntity { Id = grandChildId2, OwnerId = TestUser.User1.Id, Parent = childEntity1 };
            var grandChildId3 = Id("E106");
            var grandChildEntity3 = new TestEntity { Id = grandChildId3, OwnerId = TestUser.User1.Id, Parent = childEntity2 };

            // Calling the security component for creating entity tree
            try
            {
                context.Security.CreateSecurityEntity(rootEntity);
                context.Security.CreateSecurityEntity(childEntity1);
                context.Security.CreateSecurityEntity(childEntity2);
                context.Security.CreateSecurityEntity(grandChildEntity1);
                context.Security.CreateSecurityEntity(grandChildEntity2);
                context.Security.CreateSecurityEntity(grandChildEntity3);
            }
            catch { }

            //# Deleting an entity that has two children
            context.Security.DeleteEntity(childEntity1);

            // inspection
            Assert.IsNotNull(context.Security.GetSecurityEntity(rootId));
            Assert.IsNull(context.Security.GetSecurityEntity(childId1));
            Assert.IsNotNull(context.Security.GetSecurityEntity(childId2));
            Assert.IsNull(context.Security.GetSecurityEntity(grandChildId1));
            Assert.IsNull(context.Security.GetSecurityEntity(grandChildId2));
            Assert.IsNotNull(context.Security.GetSecurityEntity(grandChildId3));

            Assert.IsNotNull(GetStoredSecurityEntity(context, rootId));
            Assert.IsNull(GetStoredSecurityEntity(context, childId1));
            Assert.IsNotNull(GetStoredSecurityEntity(context, childId2));
            Assert.IsNull(GetStoredSecurityEntity(context, grandChildId1));
            Assert.IsNull(GetStoredSecurityEntity(context, grandChildId2));
            Assert.IsNotNull(GetStoredSecurityEntity(context, grandChildId3));
        }
        [TestMethod]
        public void Structure_Low_DeleteEntity()
        {
            // Preparing
            StartTheSystem();
            context = new Context(TestUser.User1);
            var rootId = Id("E101");
            var rootEntity = new TestEntity { Id = rootId, OwnerId = TestUser.User1.Id, Parent = null };
            var childId1 = Id("E102");
            var childEntity1 = new TestEntity { Id = childId1, OwnerId = TestUser.User1.Id, Parent = rootEntity };
            var childId2 = Id("E103");
            var childEntity2 = new TestEntity { Id = childId2, OwnerId = TestUser.User1.Id, Parent = rootEntity };
            var grandChildId1 = Id("E104");
            var grandChildEntity1 = new TestEntity { Id = grandChildId1, OwnerId = TestUser.User1.Id, Parent = childEntity1 };
            var grandChildId2 = Id("E105");
            var grandChildEntity2 = new TestEntity { Id = grandChildId2, OwnerId = TestUser.User1.Id, Parent = childEntity1 };
            var grandChildId3 = Id("E106");
            var grandChildEntity3 = new TestEntity { Id = grandChildId3, OwnerId = TestUser.User1.Id, Parent = childEntity2 };

            // Calling the security component for creating entity tree
            try
            {
                context.Security.CreateSecurityEntity(rootEntity);
                context.Security.CreateSecurityEntity(childEntity1);
                context.Security.CreateSecurityEntity(childEntity2);
                context.Security.CreateSecurityEntity(grandChildEntity1);
                context.Security.CreateSecurityEntity(grandChildEntity2);
                context.Security.CreateSecurityEntity(grandChildEntity3);
            }
            catch { }

            //# Deleting an entity that has two children

            context.Security.DeleteEntity(childId1);

            // inspection
            Assert.IsNotNull(context.Security.GetSecurityEntity(rootId));
            Assert.IsNull(context.Security.GetSecurityEntity(childId1));
            Assert.IsNotNull(context.Security.GetSecurityEntity(childId2));
            Assert.IsNull(context.Security.GetSecurityEntity(grandChildId1));
            Assert.IsNull(context.Security.GetSecurityEntity(grandChildId2));
            Assert.IsNotNull(context.Security.GetSecurityEntity(grandChildId3));

            Assert.IsNotNull(GetStoredSecurityEntity(context, rootId));
            Assert.IsNull(GetStoredSecurityEntity(context, childId1));
            Assert.IsNotNull(GetStoredSecurityEntity(context, childId2));
            Assert.IsNull(GetStoredSecurityEntity(context, grandChildId1));
            Assert.IsNull(GetStoredSecurityEntity(context, grandChildId2));
            Assert.IsNotNull(GetStoredSecurityEntity(context, grandChildId3));

        }
        [TestMethod]
        public void Structure_DeletingMissingEntityDoesNotThrows()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            context.Security.DeleteEntity(int.MaxValue);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Structure_DeleteEntity_invalidId()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            context.Security.DeleteEntity(default(int));
        }



        [TestMethod]
        public void Structure_ModifyEntity()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            var id = Id("E101");
            var entity = new TestEntity
            {
                Id = id,
                OwnerId = TestUser.User1.Id,
                Parent = null
            };

            try { context.Security.CreateSecurityEntity(entity); }
            catch { }

            entity.OwnerId = TestUser.User2.Id;

            //# calling the security component for modifying the entity data
            context.Security.ModifyEntity(entity);

            var memEntity = context.Security.GetSecurityEntity(id);
            Assert.AreEqual(id, memEntity.Id);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            var dbEntity = GetStoredSecurityEntity(context, id);
            Assert.AreEqual(id, dbEntity.Id);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);


            //# calling the security component for clearing the entity's owner
            entity.OwnerId = default(int);
            context.Security.ModifyEntity(entity);

            memEntity = context.Security.GetSecurityEntity(id);
            Assert.AreEqual(default(int), memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(context, id);
            Assert.AreEqual(default(int), dbEntity.OwnerId);

        }
        [TestMethod]
        public void Structure_ModifyEntityOwner()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            var id = Id("E101");

            try { context.Security.CreateSecurityEntity(id, default(int), TestUser.User1.Id); }
            catch { }

            //# calling the security component for modifying the entity's owner
            context.Security.ModifyEntityOwner(id, TestUser.User2.Id);

            var memEntity = context.Security.GetSecurityEntity(id);
            Assert.AreEqual(id, memEntity.Id);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            var dbEntity = GetStoredSecurityEntity(context, id);
            Assert.AreEqual(id, dbEntity.Id);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);

            //# calling the security component for clearing the entity's owner
            context.Security.ModifyEntityOwner(id, default(int));

            memEntity = context.Security.GetSecurityEntity(id);
            Assert.AreEqual(default(int), memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(context, id);
            Assert.AreEqual(default(int), dbEntity.OwnerId);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Structure_ModifyEntityOwner_invalidId()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            context.Security.ModifyEntityOwner(default(int), TestUser.User2.Id);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Structure_ModifyEntity_invalidId()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            var entity = new TestEntity { Id = default(int), OwnerId = TestUser.User1.Id, Parent = null };
            context.Security.ModifyEntity(entity);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void Structure_ModifyigEntity_missing()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, Parent = null };
            context.Security.ModifyEntity(entity);
        }



        [TestMethod]
        public void Structure_MoveEntity()
        {
            TestEntity root, source, target, child1, child2;
            CreateStructureForMoveTests(out root, out source, out target, out child1, out child2);

            //#
            context.Security.MoveEntity(source, target);

            // check in database
            var movedDbEntity = GetStoredSecurityEntity(context, source.Id);
            var targetDbEntity = GetStoredSecurityEntity(context, target.Id);
            var child1DbEntity = GetStoredSecurityEntity(context, child1.Id);
            var child2DbEntity = GetStoredSecurityEntity(context, child2.Id);
            Assert.AreEqual(movedDbEntity.ParentId, targetDbEntity.Id);

            // check in memory
            var movedEntity = context.Security.GetSecurityEntity(source.Id);
            var targetEntity = context.Security.GetSecurityEntity(target.Id);
            var child1Entity = context.Security.GetSecurityEntity(child1.Id);
            var child2Entity = context.Security.GetSecurityEntity(child2.Id);

            Assert.AreEqual(targetEntity.Id, movedEntity.Parent.Id);
            Assert.AreEqual(child1Entity.GetFirstAclId(), child1Entity.Id);
            Assert.AreEqual(child2Entity.GetFirstAclId(), target.Id);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Structure_MoveEntity_InvalidSource()
        {
            TestEntity root, source, target, child1, child2;
            CreateStructureForMoveTests(out root, out source, out target, out child1, out child2);
            source.Id = default(int);
            context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Structure_MoveEntity_InvalidTarget()
        {
            TestEntity root, source, target, child1, child2;
            CreateStructureForMoveTests(out root, out source, out target, out child1, out child2);
            target.Id = default(int);
            context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void Structure_MoveEntity_MissingSource()
        {
            TestEntity root, source, target, child1, child2;
            CreateStructureForMoveTests(out root, out source, out target, out child1, out child2);
            source.Id = Id("E101");
            context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void Structure_MoveEntity_MissingTarget()
        {
            TestEntity root, source, target, child1, child2;
            CreateStructureForMoveTests(out root, out source, out target, out child1, out child2);
            target.Id = Id("E101");
            context.Security.MoveEntity(source, target);
        }

        private void CreateStructureForMoveTests(out TestEntity root, out TestEntity source, out TestEntity target, out TestEntity child1, out TestEntity child2)
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            root = new TestEntity   { Id = Id("E201"), OwnerId = TestUser.User1.Id, Parent = null };
            source = new TestEntity { Id = Id("E202"), OwnerId = TestUser.User1.Id, Parent = root };
            target = new TestEntity { Id = Id("E203"), OwnerId = TestUser.User1.Id, Parent = root };
            child1 = new TestEntity { Id = Id("E204"), OwnerId = TestUser.User1.Id, Parent = source };
            child2 = new TestEntity { Id = Id("E205"), OwnerId = TestUser.User1.Id, Parent = source };

            // Calling the security component for creating entity tree
            //context.DataProvider._DeleteAllSecurityEntities();
            context.Security.CreateSecurityEntity(root);
            context.Security.CreateSecurityEntity(source);
            context.Security.CreateSecurityEntity(target);
            context.Security.CreateSecurityEntity(child1);
            context.Security.CreateSecurityEntity(child2);

            context.Security.CreateAclEditor()
                .Allow(root.Id, 1001, false, PermissionType.Open)
                .Allow(target.Id, 1002, false, PermissionType.Open)
                .Allow(child1.Id, 1003, false, PermissionType.Open)
                .Apply();
        }




        [TestMethod]
        public void Structure_High_BreakInheritance()
        {
            int[] ids;
            CreateStructureForInheritanceTests(out ids);

            //# calling the security component for breaking permission inheritance
            context.Security.BreakInheritance(new TestEntity { Id = ids[1], ParentId = ids[0] });

            // inspection
            StoredSecurityEntity dbEntity;
            dbEntity = GetStoredSecurityEntity(context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            SecurityEntity entity;
            entity = context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void Structure_Low_BreakInheritance()
        {
            int[] ids;
            CreateStructureForInheritanceTests(out ids);

            //# calling the security component for breaking permission inheritance
            context.Security.BreakInheritance(ids[1]);

            // inspection
            StoredSecurityEntity dbEntity;
            dbEntity = GetStoredSecurityEntity(context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            SecurityEntity entity;
            entity = context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void Structure_BreakInheritance_Breaked()
        {
            int[] ids;
            CreateStructureForInheritanceTests(out ids);

            context.Security.BreakInheritance(ids[1]);
            // valid but ineffective
            context.Security.BreakInheritance(ids[1]);

            // inspection
            StoredSecurityEntity dbEntity;
            dbEntity = GetStoredSecurityEntity(context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            SecurityEntity entity;
            entity = context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void Structure_BreakInheritance_Invalid()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            context.Security.BreakInheritance(default(int));
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void Structure_BreakInheritance_Missing()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            context.Security.BreakInheritance(int.MaxValue);
        }

        [TestMethod]
        public void Structure_High_UnbreakInheritance()
        {
            StoredSecurityEntity dbEntity;
            SecurityEntity entity;
            int[] ids;
            CreateStructureForInheritanceTests(out ids);
            context.Security.BreakInheritance(ids[1]);

            dbEntity = GetStoredSecurityEntity(context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);

            //# calling the security component for restoring breaked permission inheritance
            context.Security.UnbreakInheritance(new TestEntity { Id = ids[1], ParentId = ids[0] });

            // inspection
            dbEntity = GetStoredSecurityEntity(context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[1]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            entity = context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[1]);
            Assert.IsTrue(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void Structure_Low_UnbreakInheritance()
        {
            StoredSecurityEntity dbEntity;
            SecurityEntity entity;
            int[] ids;
            CreateStructureForInheritanceTests(out ids);
            context.Security.BreakInheritance(ids[1]);

            dbEntity = GetStoredSecurityEntity(context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);

            //# calling the security component for restoring breaked permission inheritance
            context.Security.UnbreakInheritance(ids[1]);

            // inspection
            dbEntity = GetStoredSecurityEntity(context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[1]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            entity = context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[1]);
            Assert.IsTrue(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void Structure_UnbreakInheritance_Unbreaked()
        {
            StoredSecurityEntity dbEntity;
            SecurityEntity entity;
            int[] ids;
            CreateStructureForInheritanceTests(out ids);
            context.Security.BreakInheritance(ids[1]);

            //#
            context.Security.UnbreakInheritance(ids[1]);
            //# valid but ineffective
            context.Security.UnbreakInheritance(ids[1]);

            // inspection
            dbEntity = GetStoredSecurityEntity(context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[1]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            entity = context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[1]);
            Assert.IsTrue(entity.IsInherited);
            entity = context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void Structure_UnbreakInheritance_Invalid()
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            context.Security.UnbreakInheritance(default(int));
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void Structure_UnbreakInheritance_Missing()
        {
            Debug.WriteLine("SECU> START TEST: Structure_UnbreakInheritance_Missing");
            StartTheSystem();
            context = new Context(TestUser.User1);
            context.Security.UnbreakInheritance(int.MaxValue);
            Debug.WriteLine("SECU> END   TEST: Structure_UnbreakInheritance_Missing");
        }



        [TestMethod]
        public void Structure_MemParentChildren_Initial()
        {
            context = Tools.GetEmptyContext(TestUser.User1);
            var ctx = context.Security;
            var repo = Tools.CreateRepository(ctx);

            var expected = "{E1{E2{E5{E14{E50{E51{E52}E53}}E15}E6{E16E17}E7{E18E19}}E3{E8{E20E21{E22E23E24E25E26E27E28E29}}E9E10}E4{E11E12{E30{E31{E33E34{E40E43{E44E45E46E47E48E49}}}E32{E35{E41{E42}}E36{E37{E38E39}}}}}E13}}}";
            var actual = Tools.EntityIdStructureToString(ctx);

            Assert.AreEqual(expected, actual);
        }
        [TestMethod]
        public void Structure_MemParentChildren_CreateUnderLeaf()
        {
            context = Tools.GetEmptyContext(TestUser.User1);
            var ctx = context.Security;
            var repo = Tools.CreateRepository(ctx);

            ctx.CreateSecurityEntity(Id("E54"), Id("E53"), 1);

            var expected = "{E1{E2{E5{E14{E50{E51{E52}E53{E54}}}E15}E6{E16E17}E7{E18E19}}E3{E8{E20E21{E22E23E24E25E26E27E28E29}}E9E10}E4{E11E12{E30{E31{E33E34{E40E43{E44E45E46E47E48E49}}}E32{E35{E41{E42}}E36{E37{E38E39}}}}}E13}}}";
            var actual = Tools.EntityIdStructureToString(ctx);

            Assert.AreEqual(expected, actual);
        }
        [TestMethod]
        public void Structure_MemParentChildren_CreateUnderNotLeaf()
        {
            context = Tools.GetEmptyContext(TestUser.User1);
            var ctx = context.Security;
            var repo = Tools.CreateRepository(ctx);

            ctx.CreateSecurityEntity(Id("E54"), Id("E50"), 1);

            var expected = "{E1{E2{E5{E14{E50{E51{E52}E53E54}}E15}E6{E16E17}E7{E18E19}}E3{E8{E20E21{E22E23E24E25E26E27E28E29}}E9E10}E4{E11E12{E30{E31{E33E34{E40E43{E44E45E46E47E48E49}}}E32{E35{E41{E42}}E36{E37{E38E39}}}}}E13}}}";
            var actual = Tools.EntityIdStructureToString(ctx);

            Assert.AreEqual(expected, actual);
        }
        public void Structure_MemParentChildren_DeleteTheLastOne()
        {
            context = Tools.GetEmptyContext(TestUser.User1);
            var ctx = context.Security;
            var repo = Tools.CreateRepository(ctx);

            ctx.DeleteEntity(Id("E52"));

            var expected = "{E1{E2{E5{E14{E50{E51E53}}E15}E6{E16E17}E7{E18E19}}E3{E8{E20E21{E22E23E24E25E26E27E28E29}}E9E10}E4{E11E12{E30{E31{E33E34{E40E43{E44E45E46E47E48E49}}}E32{E35{E41{E42}}E36{E37{E38E39}}}}}E13}}}";
            var actual = Tools.EntityIdStructureToString(ctx);

            Assert.AreEqual(expected, actual);
        }
        [TestMethod]
        public void Structure_MemParentChildren_DeleteNotLast()
        {
            context = Tools.GetEmptyContext(TestUser.User1);
            var ctx = context.Security;
            var repo = Tools.CreateRepository(ctx);

            ctx.DeleteEntity(Id("E25"));

            var expected = "{E1{E2{E5{E14{E50{E51{E52}E53}}E15}E6{E16E17}E7{E18E19}}E3{E8{E20E21{E22E23E24E26E27E28E29}}E9E10}E4{E11E12{E30{E31{E33E34{E40E43{E44E45E46E47E48E49}}}E32{E35{E41{E42}}E36{E37{E38E39}}}}}E13}}}";
            var actual = Tools.EntityIdStructureToString(ctx);

            Assert.AreEqual(expected, actual);
        }
        [TestMethod]
        public void Structure_MemParentChildren_MoveUnderLeaf()
        {
            context = Tools.GetEmptyContext(TestUser.User1);
            var ctx = context.Security;
            var repo = Tools.CreateRepository(ctx);

            ctx.MoveEntity(Id("E50"), Id("E15"));

            var expected = "{E1{E2{E5{E14E15{E50{E51{E52}E53}}}E6{E16E17}E7{E18E19}}E3{E8{E20E21{E22E23E24E25E26E27E28E29}}E9E10}E4{E11E12{E30{E31{E33E34{E40E43{E44E45E46E47E48E49}}}E32{E35{E41{E42}}E36{E37{E38E39}}}}}E13}}}";
            var actual = Tools.EntityIdStructureToString(ctx);

            Assert.AreEqual(expected, actual);
        }
        [TestMethod]
        public void Structure_MemParentChildren_MoveUnderNotLeaf()
        {
            context = Tools.GetEmptyContext(TestUser.User1);
            var ctx = context.Security;
            var repo = Tools.CreateRepository(ctx);

            ctx.MoveEntity(Id("E50"), Id("E2"));

            var expected = "{E1{E2{E5{E14E15}E6{E16E17}E7{E18E19}E50{E51{E52}E53}}E3{E8{E20E21{E22E23E24E25E26E27E28E29}}E9E10}E4{E11E12{E30{E31{E33E34{E40E43{E44E45E46E47E48E49}}}E32{E35{E41{E42}}E36{E37{E38E39}}}}}E13}}}";
            var actual = Tools.EntityIdStructureToString(ctx);

            Assert.AreEqual(expected, actual);
        }
        [TestMethod]
        public void Structure_MemParentChildren_MoveSiblingToSibling()
        {
            context = Tools.GetEmptyContext(TestUser.User1);
            var ctx = context.Security;
            var repo = Tools.CreateRepository(ctx);

            ctx.MoveEntity(Id("E6"), Id("E3"));

            var expected = "{E1{E2{E5{E14{E50{E51{E52}E53}}E15}E7{E18E19}}E3{E6{E16E17}E8{E20E21{E22E23E24E25E26E27E28E29}}E9E10}E4{E11E12{E30{E31{E33E34{E40E43{E44E45E46E47E48E49}}}E32{E35{E41{E42}}E36{E37{E38E39}}}}}E13}}}";
            var actual = Tools.EntityIdStructureToString(ctx);

            Assert.AreEqual(expected, actual);
        }


        [TestMethod]
        public void Structure_ResolveMissingEntity()
        {
            context = Tools.GetEmptyContext(TestUser.User1);
            var ctx = new MissingEntityResolverContext(TestUser.User1);
            var contextAcc = new PrivateObject(context);
            contextAcc.SetFieldOrProperty("Security", ctx);

            //----

            try
            {
                var entity = context.Security.GetSecurityEntity(17, false);
                Assert.IsNull(entity);
                entity = context.Security.GetSecurityEntity(42, false);
                Assert.IsNotNull(entity);
                Assert.AreEqual(17, entity.OwnerId);
            }
            finally
            {
                ctx.Cache.Entities.Clear();
            }
        }


        private void StartTheSystem()
        {
            SecurityActivityQueue._setCurrentExecutionState(new CompletionState());
            MemoryDataProvider._lastActivityId = 0;
            Context.StartTheSystem(new MemoryDataProvider(DatabaseStorage.CreateEmpty()), new DefaultMessageProvider());
        }

        private void CreateStructureForInheritanceTests(out int[] chain)
        {
            StartTheSystem();
            context = new Context(TestUser.User1);
            var rootEntity = new TestEntity       { Id = Id("E251"), OwnerId = TestUser.User1.Id, Parent = null };
            var childEntity = new TestEntity      { Id = Id("E252"), OwnerId = TestUser.User1.Id, Parent = rootEntity };
            var grandChildEntity = new TestEntity { Id = Id("E253"), OwnerId = TestUser.User1.Id, Parent = childEntity };

            try
            {
                context.Security.CreateSecurityEntity(rootEntity);
                context.Security.CreateSecurityEntity(childEntity);
                context.Security.CreateSecurityEntity(grandChildEntity);
            }
            catch { }

            chain = new[] { rootEntity.Id, childEntity.Id, grandChildEntity.Id };
        }

        private StoredSecurityEntity GetStoredSecurityEntity(Context context, int entityId)
        {
            return DataHandler.GetStoredSecurityEntity(context.Security.DataProvider, entityId);
        }

        private int Id(string name)
        {
            return Tools.GetId(name);
        }



        private class MissingEntityResolverContext : TestSecurityContext
        {
            public MissingEntityResolverContext(ISecurityUser user) : base(user) { }
            protected internal override bool GetMissingEntity(int entityId, out int parentId, out int ownerId)
            {
                parentId = 0;
                ownerId = 0;
                if (entityId != 42)
                    return false;

                ownerId = 17;
                return true;
            }
        }
    }
}
