using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security;
using SenseNet.Security.EF6SecurityStore;
using SenseNet.Security.EFCSecurityStore;
using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class EFStructureTests
    {
        Context context;
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
            Tools.CheckIntegrity(TestContext.TestName, context.Security);
        }

        private Context Start()
        {
            Context.StartTheSystem(new EFCSecurityDataProvider(), new DefaultMessageProvider());
            return new Context(TestUser.User1);
        }

        [TestMethod]
        public void EF_Structure_High_CreateRootEntity()
        {
            context = Start();

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
        public void EF_Structure_Low_CreateRootEntity()
        {
            context = Start();

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
        public void EF_Structure_CreateChildEntityChain()
        {
            // Preparing
            context = Start();

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
        public void EF_Structure_CreateChildEntityChainByIds()
        {
            // Preparing
            context = Start();

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
        public void EF_Structure_EntityLevel()
        {
            // Preparing
            context = Start();

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
        public void EF_Structure_CreateSecurityEntity_invalidId()
        {
            context = Start();
            //# calling the security component
            context.Security.CreateSecurityEntity(default(int), default(int), default(int));
        }
        [TestMethod]
        public void EF_Structure_CreateSecurityEntity_existing()
        {
            context = Start();
            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, Parent = null };
            context.Security.CreateSecurityEntity(entity);
            entity.OwnerId = TestUser.User2.Id;
            context.Security.CreateSecurityEntity(entity);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF_Structure_CreateSecurityEntity_missingParent()
        {
            context = Start();
            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, ParentId = int.MaxValue };
            context.Security.CreateSecurityEntity(entity);
        }

        [TestMethod]
        public void EF_Structure_High_DeleteEntity()
        {
            // Preparing
            context = Start();

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
        public void EF_Structure_Low_DeleteEntity()
        {
            // Preparing
            context = Start();

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
        public void EF_Structure_DeletingMissingEntityDoesNotThrows()
        {
            context = Start();

            context.Security.DeleteEntity(int.MaxValue);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EF_Structure_DeleteEntity_invalidId()
        {
            context = Start();

            context.Security.DeleteEntity(default(int));
        }



        [TestMethod]
        public void EF_Structure_ModifyEntity()
        {
            context = Start();

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
        public void EF_Structure_ModifyEntityOwner()
        {
            context = Start();

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
        public void EF_Structure_ModifyEntityOwner_invalidId()
        {
            context = Start();

            context.Security.ModifyEntityOwner(default(int), TestUser.User2.Id);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EF_Structure_ModifyEntity_invalidId()
        {
            context = Start();

            var entity = new TestEntity { Id = default(int), OwnerId = TestUser.User1.Id, Parent = null };
            context.Security.ModifyEntity(entity);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF_Structure_ModifyigEntity_missing()
        {
            context = Start();

            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, Parent = null };
            context.Security.ModifyEntity(entity);
        }



        [TestMethod]
        public void EF_Structure_MoveEntity()
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
        public void EF_Structure_MoveEntity_InvalidSource()
        {
            TestEntity root, source, target, child1, child2;
            CreateStructureForMoveTests(out root, out source, out target, out child1, out child2);
            source.Id = default(int);
            context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EF_Structure_MoveEntity_InvalidTarget()
        {
            TestEntity root, source, target, child1, child2;
            CreateStructureForMoveTests(out root, out source, out target, out child1, out child2);
            target.Id = default(int);
            context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF_Structure_MoveEntity_MissingSource()
        {
            TestEntity root, source, target, child1, child2;
            CreateStructureForMoveTests(out root, out source, out target, out child1, out child2);
            source.Id = Id("E101");
            context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF_Structure_MoveEntity_MissingTarget()
        {
            TestEntity root, source, target, child1, child2;
            CreateStructureForMoveTests(out root, out source, out target, out child1, out child2);
            target.Id = Id("E101");
            context.Security.MoveEntity(source, target);
        }

        private void CreateStructureForMoveTests(out TestEntity root, out TestEntity source, out TestEntity target, out TestEntity child1, out TestEntity child2)
        {
            context = Start();

            root = new TestEntity { Id = Id("E201"), OwnerId = TestUser.User1.Id, Parent = null };
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
        public void EF_Structure_High_BreakInheritance()
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
        public void EF_Structure_Low_BreakInheritance()
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
        public void EF_Structure_BreakInheritance_Breaked()
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
        public void EF_Structure_BreakInheritance_Invalid()
        {
            context = Start();

            context.Security.BreakInheritance(default(int));
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF_Structure_BreakInheritance_Missing()
        {
            context = Start();

            context.Security.BreakInheritance(int.MaxValue);
        }

        [TestMethod]
        public void EF_Structure_High_UnbreakInheritance()
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
        public void EF_Structure_Low_UnbreakInheritance()
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
        public void EF_Structure_UnbreakInheritance_Unbreaked()
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
        public void EF_Structure_UnbreakInheritance_Invalid()
        {
            context = Start();

            context.Security.UnbreakInheritance(default(int));
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF_Structure_UnbreakInheritance_Missing()
        {
            context = Start();

            context.Security.UnbreakInheritance(int.MaxValue);
        }




        private void CreateStructureForInheritanceTests(out int[] chain)
        {
            context = Start();

            var rootEntity = new TestEntity { Id = Id("E251"), OwnerId = TestUser.User1.Id, Parent = null };
            var childEntity = new TestEntity { Id = Id("E252"), OwnerId = TestUser.User1.Id, Parent = rootEntity };
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


    }
}
