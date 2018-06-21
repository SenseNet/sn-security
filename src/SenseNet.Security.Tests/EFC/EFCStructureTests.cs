using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.EFCSecurityStore;
using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;
// ReSharper disable InconsistentNaming
// ReSharper disable UnusedVariable

namespace SenseNet.Security.Tests.EFC
{
    [TestClass]
    public class EFCStructureTests : EFCTestBase
    {
        protected override Context CreateContext(TextWriter traceChannel = null)
        {
            Context.StartTheSystem(new EFCSecurityDataProvider(), new DefaultMessageProvider(), traceChannel);
            return new Context(TestUser.User1);
        }

        [TestMethod]
        public void EFC_Structure_High_CreateRootEntity()
        {
            var id = Id("E101");
            var entity = new TestEntity { Id = id, OwnerId = TestUser.User1.Id, Parent = null };

            //# calling the security component
            Context.Security.CreateSecurityEntity(entity);

            var dbEntity = GetStoredSecurityEntity(Context, id);
            var memEntity = Context.Security.GetSecurityEntity(id);

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
        public void EFC_Structure_Low_CreateRootEntity()
        {
            var id = Id("E101");

            //# calling the security component for creating one entity
            Context.Security.CreateSecurityEntity(id, default(int), TestUser.User1.Id);

            var dbEntity = GetStoredSecurityEntity(Context, id);
            var memEntity = Context.Security.GetSecurityEntity(id);

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
        public void EFC_Structure_CreateChildEntityChain()
        {
            // Preparing
            var rootId = Id("E101");
            var rootEntity = new TestEntity { Id = rootId, OwnerId = TestUser.User1.Id, Parent = null };
            var childId = Id("E102");
            var childEntity = new TestEntity { Id = childId, OwnerId = TestUser.User2.Id, Parent = rootEntity };
            var grandChildId = Id("E103");
            var grandChildEntity = new TestEntity { Id = grandChildId, OwnerId = TestUser.User3.Id, Parent = childEntity };

            //# calling the security component for creating an entity chain
            Context.Security.CreateSecurityEntity(rootEntity);
            Context.Security.CreateSecurityEntity(childEntity);
            Context.Security.CreateSecurityEntity(grandChildEntity);

            // inspection
            var memEntity = Context.Security.GetSecurityEntity(rootId);
            Assert.AreEqual(0, memEntity.Level);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User1.Id, memEntity.OwnerId);
            var dbEntity = GetStoredSecurityEntity(Context, rootId);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User1.Id, dbEntity.OwnerId);

            memEntity = Context.Security.GetSecurityEntity(childId);
            Assert.AreEqual(1, memEntity.Level);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(Context, childId);
            Assert.AreEqual(rootId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);

            memEntity = Context.Security.GetSecurityEntity(grandChildId);
            Assert.AreEqual(2, memEntity.Level);
            Assert.AreEqual(childId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User3.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(Context, grandChildId);
            Assert.AreEqual(childId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User3.Id, dbEntity.OwnerId);
        }
        [TestMethod]
        public void EFC_Structure_CreateChildEntityChainByIds()
        {
            // Preparing
            var rootId = Id("E101");
            var childId = Id("E102");
            var grandChildId = Id("E103");

            //# calling the security component for creating an entity chain
            Context.Security.CreateSecurityEntity(rootId, default(int), TestUser.User1.Id);
            Context.Security.CreateSecurityEntity(childId, rootId, TestUser.User2.Id);
            Context.Security.CreateSecurityEntity(grandChildId, childId, TestUser.User3.Id);

            // inspection
            var db = new PrivateObject(Context.Security.DataProvider);
            var memEntity = Context.Security.GetSecurityEntity(rootId);
            Assert.AreEqual(0, memEntity.Level);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User1.Id, memEntity.OwnerId);
            var dbEntity = GetStoredSecurityEntity(Context, rootId);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User1.Id, dbEntity.OwnerId);

            memEntity = Context.Security.GetSecurityEntity(childId);
            Assert.AreEqual(1, memEntity.Level);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(Context, childId);
            Assert.AreEqual(rootId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);

            memEntity = Context.Security.GetSecurityEntity(grandChildId);
            Assert.AreEqual(2, memEntity.Level);
            Assert.AreEqual(childId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User3.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(Context, grandChildId);
            Assert.AreEqual(childId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User3.Id, dbEntity.OwnerId);
        }
        [TestMethod]
        public void EFC_Structure_EntityLevel()
        {
            // Preparing
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
            Context.Security.CreateSecurityEntity(rootEntity);
            Context.Security.CreateSecurityEntity(childEntity1);
            Context.Security.CreateSecurityEntity(childEntity2);
            Context.Security.CreateSecurityEntity(grandChildEntity1);
            Context.Security.CreateSecurityEntity(grandChildEntity2);
            Context.Security.CreateSecurityEntity(grandChildEntity3);

            // checking target object structure in memory
            var entity = Context.Security.GetSecurityEntity(rootId);
            Assert.AreEqual(0, entity.Level);
            entity = Context.Security.GetSecurityEntity(childId1);
            Assert.AreEqual(1, entity.Level);
            entity = Context.Security.GetSecurityEntity(childId2);
            Assert.AreEqual(1, entity.Level);
            entity = Context.Security.GetSecurityEntity(grandChildId1);
            Assert.AreEqual(2, entity.Level);
            entity = Context.Security.GetSecurityEntity(grandChildId2);
            Assert.AreEqual(2, entity.Level);
            entity = Context.Security.GetSecurityEntity(grandChildId3);
            Assert.AreEqual(2, entity.Level);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EFC_Structure_CreateSecurityEntity_invalidId()
        {
            //# calling the security component
            Context.Security.CreateSecurityEntity(default(int), default(int), default(int));
        }
        [TestMethod]
        public void EFC_Structure_CreateSecurityEntity_existing()
        {
            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, Parent = null };
            Context.Security.CreateSecurityEntity(entity);
            entity.OwnerId = TestUser.User2.Id;
            Context.Security.CreateSecurityEntity(entity);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EFC_Structure_CreateSecurityEntity_missingParent()
        {
            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, ParentId = int.MaxValue };
            Context.Security.CreateSecurityEntity(entity);
        }

        [TestMethod]
        public void EFC_Structure_High_DeleteEntity()
        {
            // Preparing
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
                Context.Security.CreateSecurityEntity(rootEntity);
                Context.Security.CreateSecurityEntity(childEntity1);
                Context.Security.CreateSecurityEntity(childEntity2);
                Context.Security.CreateSecurityEntity(grandChildEntity1);
                Context.Security.CreateSecurityEntity(grandChildEntity2);
                Context.Security.CreateSecurityEntity(grandChildEntity3);
            }
            catch
            {
                // ignored
            }

            //# Deleting an entity that has two children
            Context.Security.DeleteEntity(childEntity1);

            // inspection
            Assert.IsNotNull(Context.Security.GetSecurityEntity(rootId));
            Assert.IsNull(Context.Security.GetSecurityEntity(childId1));
            Assert.IsNotNull(Context.Security.GetSecurityEntity(childId2));
            Assert.IsNull(Context.Security.GetSecurityEntity(grandChildId1));
            Assert.IsNull(Context.Security.GetSecurityEntity(grandChildId2));
            Assert.IsNotNull(Context.Security.GetSecurityEntity(grandChildId3));

            Assert.IsNotNull(GetStoredSecurityEntity(Context, rootId));
            Assert.IsNull(GetStoredSecurityEntity(Context, childId1));
            Assert.IsNotNull(GetStoredSecurityEntity(Context, childId2));
            Assert.IsNull(GetStoredSecurityEntity(Context, grandChildId1));
            Assert.IsNull(GetStoredSecurityEntity(Context, grandChildId2));
            Assert.IsNotNull(GetStoredSecurityEntity(Context, grandChildId3));
        }
        [TestMethod]
        public void EFC_Structure_Low_DeleteEntity()
        {
            // Preparing
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
                Context.Security.CreateSecurityEntity(rootEntity);
                Context.Security.CreateSecurityEntity(childEntity1);
                Context.Security.CreateSecurityEntity(childEntity2);
                Context.Security.CreateSecurityEntity(grandChildEntity1);
                Context.Security.CreateSecurityEntity(grandChildEntity2);
                Context.Security.CreateSecurityEntity(grandChildEntity3);
            }
            catch
            {
                // ignored
            }

            //# Deleting an entity that has two children

            Context.Security.DeleteEntity(childId1);

            // inspection
            Assert.IsNotNull(Context.Security.GetSecurityEntity(rootId));
            Assert.IsNull(Context.Security.GetSecurityEntity(childId1));
            Assert.IsNotNull(Context.Security.GetSecurityEntity(childId2));
            Assert.IsNull(Context.Security.GetSecurityEntity(grandChildId1));
            Assert.IsNull(Context.Security.GetSecurityEntity(grandChildId2));
            Assert.IsNotNull(Context.Security.GetSecurityEntity(grandChildId3));

            Assert.IsNotNull(GetStoredSecurityEntity(Context, rootId));
            Assert.IsNull(GetStoredSecurityEntity(Context, childId1));
            Assert.IsNotNull(GetStoredSecurityEntity(Context, childId2));
            Assert.IsNull(GetStoredSecurityEntity(Context, grandChildId1));
            Assert.IsNull(GetStoredSecurityEntity(Context, grandChildId2));
            Assert.IsNotNull(GetStoredSecurityEntity(Context, grandChildId3));

        }
        [TestMethod]
        public void EFC_Structure_DeletingMissingEntityDoesNotThrows()
        {
            Context.Security.DeleteEntity(int.MaxValue);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EFC_Structure_DeleteEntity_invalidId()
        {
            Context.Security.DeleteEntity(default(int));
        }



        [TestMethod]
        public void EFC_Structure_ModifyEntity()
        {
            var id = Id("E101");
            var entity = new TestEntity
            {
                Id = id,
                OwnerId = TestUser.User1.Id,
                Parent = null
            };

            try { Context.Security.CreateSecurityEntity(entity); }
            catch
            {
                // ignored
            }

            entity.OwnerId = TestUser.User2.Id;

            //# calling the security component for modifying the entity data
            Context.Security.ModifyEntity(entity);

            var memEntity = Context.Security.GetSecurityEntity(id);
            Assert.AreEqual(id, memEntity.Id);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            var dbEntity = GetStoredSecurityEntity(Context, id);
            Assert.AreEqual(id, dbEntity.Id);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);


            //# calling the security component for clearing the entity's owner
            entity.OwnerId = default(int);
            Context.Security.ModifyEntity(entity);

            memEntity = Context.Security.GetSecurityEntity(id);
            Assert.AreEqual(default(int), memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(Context, id);
            Assert.AreEqual(default(int), dbEntity.OwnerId);

        }
        [TestMethod]
        public void EFC_Structure_ModifyEntityOwner()
        {
            var id = Id("E101");

            try { Context.Security.CreateSecurityEntity(id, default(int), TestUser.User1.Id); }
            catch
            {
                // ignored
            }

            //# calling the security component for modifying the entity's owner
            Context.Security.ModifyEntityOwner(id, TestUser.User2.Id);

            var memEntity = Context.Security.GetSecurityEntity(id);
            Assert.AreEqual(id, memEntity.Id);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            var dbEntity = GetStoredSecurityEntity(Context, id);
            Assert.AreEqual(id, dbEntity.Id);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);

            //# calling the security component for clearing the entity's owner
            Context.Security.ModifyEntityOwner(id, default(int));

            memEntity = Context.Security.GetSecurityEntity(id);
            Assert.AreEqual(default(int), memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(Context, id);
            Assert.AreEqual(default(int), dbEntity.OwnerId);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EFC_Structure_ModifyEntityOwner_invalidId()
        {
            Context.Security.ModifyEntityOwner(default(int), TestUser.User2.Id);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EFC_Structure_ModifyEntity_invalidId()
        {
            var entity = new TestEntity { Id = default(int), OwnerId = TestUser.User1.Id, Parent = null };
            Context.Security.ModifyEntity(entity);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EFC_Structure_ModifyigEntity_missing()
        {
            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, Parent = null };
            Context.Security.ModifyEntity(entity);
        }



        [TestMethod]
        public void EFC_Structure_MoveEntity()
        {
            CreateStructureForMoveTests(out var root, out var source, out var target, out var child1, out var child2);

            //#
            Context.Security.MoveEntity(source, target);

            // check in database
            var movedDbEntity = GetStoredSecurityEntity(Context, source.Id);
            var targetDbEntity = GetStoredSecurityEntity(Context, target.Id);
            var child1DbEntity = GetStoredSecurityEntity(Context, child1.Id);
            var child2DbEntity = GetStoredSecurityEntity(Context, child2.Id);
            Assert.AreEqual(movedDbEntity.ParentId, targetDbEntity.Id);

            // check in memory
            var movedEntity = Context.Security.GetSecurityEntity(source.Id);
            var targetEntity = Context.Security.GetSecurityEntity(target.Id);
            var child1Entity = Context.Security.GetSecurityEntity(child1.Id);
            var child2Entity = Context.Security.GetSecurityEntity(child2.Id);

            Assert.AreEqual(targetEntity.Id, movedEntity.Parent.Id);
            Assert.AreEqual(child1Entity.GetFirstAclId(), child1Entity.Id);
            Assert.AreEqual(child2Entity.GetFirstAclId(), target.Id);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EFC_Structure_MoveEntity_InvalidSource()
        {
            CreateStructureForMoveTests(out var root, out var source, out var target, out var child1, out var child2);
            source.Id = default(int);
            Context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EFC_Structure_MoveEntity_InvalidTarget()
        {
            CreateStructureForMoveTests(out var root, out var source, out var target, out var child1, out var child2);
            target.Id = default(int);
            Context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EFC_Structure_MoveEntity_MissingSource()
        {
            CreateStructureForMoveTests(out var root, out var source, out var target, out var child1, out var child2);
            source.Id = Id("E101");
            Context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EFC_Structure_MoveEntity_MissingTarget()
        {
            CreateStructureForMoveTests(out var root, out var source, out var target, out var child1, out var child2);
            target.Id = Id("E101");
            Context.Security.MoveEntity(source, target);
        }

        private void CreateStructureForMoveTests(out TestEntity root, out TestEntity source, out TestEntity target, out TestEntity child1, out TestEntity child2)
        {
            root = new TestEntity { Id = Id("E201"), OwnerId = TestUser.User1.Id, Parent = null };
            source = new TestEntity { Id = Id("E202"), OwnerId = TestUser.User1.Id, Parent = root };
            target = new TestEntity { Id = Id("E203"), OwnerId = TestUser.User1.Id, Parent = root };
            child1 = new TestEntity { Id = Id("E204"), OwnerId = TestUser.User1.Id, Parent = source };
            child2 = new TestEntity { Id = Id("E205"), OwnerId = TestUser.User1.Id, Parent = source };

            // Calling the security component for creating entity tree
            //context.DataProvider._DeleteAllSecurityEntities();
            Context.Security.CreateSecurityEntity(root);
            Context.Security.CreateSecurityEntity(source);
            Context.Security.CreateSecurityEntity(target);
            Context.Security.CreateSecurityEntity(child1);
            Context.Security.CreateSecurityEntity(child2);

            Context.Security.CreateAclEditor()
                .Allow(root.Id, 1001, false, PermissionType.Open)
                .Allow(target.Id, 1002, false, PermissionType.Open)
                .Allow(child1.Id, 1003, false, PermissionType.Open)
                .Apply();
        }




        [TestMethod]
        public void EFC_Structure_High_BreakInheritance()
        {
            CreateStructureForInheritanceTests(out var ids);

            //# calling the security component for breaking permission inheritance
            Context.Security.BreakInheritance(new TestEntity { Id = ids[1], ParentId = ids[0] });

            // inspection
            var dbEntity = GetStoredSecurityEntity(Context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            var entity = Context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void EFC_Structure_Low_BreakInheritance()
        {
            CreateStructureForInheritanceTests(out var ids);

            //# calling the security component for breaking permission inheritance
            Context.Security.BreakInheritance(ids[1]);

            // inspection
            var dbEntity = GetStoredSecurityEntity(Context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            var entity = Context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void EFC_Structure_BreakInheritance_Breaked()
        {
            CreateStructureForInheritanceTests(out var ids);

            Context.Security.BreakInheritance(ids[1]);
            // valid but ineffective
            Context.Security.BreakInheritance(ids[1]);

            // inspection
            var dbEntity = GetStoredSecurityEntity(Context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            var entity = Context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EFC_Structure_BreakInheritance_Invalid()
        {
            Context.Security.BreakInheritance(default(int));
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EFC_Structure_BreakInheritance_Missing()
        {
            Context.Security.BreakInheritance(int.MaxValue);
        }

        [TestMethod]
        public void EFC_Structure_High_UnbreakInheritance()
        {
            CreateStructureForInheritanceTests(out var ids);
            Context.Security.BreakInheritance(ids[1]);

            var dbEntity = GetStoredSecurityEntity(Context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            var entity = Context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);

            //# calling the security component for restoring breaked permission inheritance
            Context.Security.UnbreakInheritance(new TestEntity { Id = ids[1], ParentId = ids[0] });

            // inspection
            dbEntity = GetStoredSecurityEntity(Context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[1]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            entity = Context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[1]);
            Assert.IsTrue(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void EFC_Structure_Low_UnbreakInheritance()
        {
            CreateStructureForInheritanceTests(out var ids);
            Context.Security.BreakInheritance(ids[1]);

            var dbEntity = GetStoredSecurityEntity(Context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            var entity = Context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);

            //# calling the security component for restoring breaked permission inheritance
            Context.Security.UnbreakInheritance(ids[1]);

            // inspection
            dbEntity = GetStoredSecurityEntity(Context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[1]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            entity = Context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[1]);
            Assert.IsTrue(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void EFC_Structure_UnbreakInheritance_Unbreaked()
        {
            CreateStructureForInheritanceTests(out var ids);
            Context.Security.BreakInheritance(ids[1]);

            //#
            Context.Security.UnbreakInheritance(ids[1]);
            //# valid but ineffective
            Context.Security.UnbreakInheritance(ids[1]);

            // inspection
            var dbEntity = GetStoredSecurityEntity(Context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[1]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(Context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            var entity = Context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[1]);
            Assert.IsTrue(entity.IsInherited);
            entity = Context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EFC_Structure_UnbreakInheritance_Invalid()
        {
            Context.Security.UnbreakInheritance(default(int));
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EFC_Structure_UnbreakInheritance_Missing()
        {
            Context.Security.UnbreakInheritance(int.MaxValue);
        }




        private void CreateStructureForInheritanceTests(out int[] chain)
        {
            var rootEntity = new TestEntity { Id = Id("E251"), OwnerId = TestUser.User1.Id, Parent = null };
            var childEntity = new TestEntity { Id = Id("E252"), OwnerId = TestUser.User1.Id, Parent = rootEntity };
            var grandChildEntity = new TestEntity { Id = Id("E253"), OwnerId = TestUser.User1.Id, Parent = childEntity };

            try
            {
                Context.Security.CreateSecurityEntity(rootEntity);
                Context.Security.CreateSecurityEntity(childEntity);
                Context.Security.CreateSecurityEntity(grandChildEntity);
            }
            catch
            {
                // ignored
            }

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
