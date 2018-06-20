using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.EF6SecurityStore;
using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;
// ReSharper disable InconsistentNaming
// ReSharper disable UnusedVariable

namespace SenseNet.Security.Tests.EF6
{
    [TestClass]
    public class EF6StructureTests
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

        private Context Start()
        {
            Context.StartTheSystem(new EF6SecurityDataProvider(), new DefaultMessageProvider());
            return new Context(TestUser.User1);
        }

        [TestMethod]
        public void EF6_Structure_High_CreateRootEntity()
        {
            _context = Start();

            var id = Id("E101");
            var entity = new TestEntity { Id = id, OwnerId = TestUser.User1.Id, Parent = null };

            //# calling the security component
            _context.Security.CreateSecurityEntity(entity);

            var dbEntity = GetStoredSecurityEntity(_context, id);
            var memEntity = _context.Security.GetSecurityEntity(id);

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
        public void EF6_Structure_Low_CreateRootEntity()
        {
            _context = Start();

            var id = Id("E101");

            //# calling the security component for creating one entity
            _context.Security.CreateSecurityEntity(id, default(int), TestUser.User1.Id);

            var dbEntity = GetStoredSecurityEntity(_context, id);
            var memEntity = _context.Security.GetSecurityEntity(id);

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
        public void EF6_Structure_CreateChildEntityChain()
        {
            // Preparing
            _context = Start();

            var rootId = Id("E101");
            var rootEntity = new TestEntity { Id = rootId, OwnerId = TestUser.User1.Id, Parent = null };
            var childId = Id("E102");
            var childEntity = new TestEntity { Id = childId, OwnerId = TestUser.User2.Id, Parent = rootEntity };
            var grandChildId = Id("E103");
            var grandChildEntity = new TestEntity { Id = grandChildId, OwnerId = TestUser.User3.Id, Parent = childEntity };

            //# calling the security component for creating an entity chain
            _context.Security.CreateSecurityEntity(rootEntity);
            _context.Security.CreateSecurityEntity(childEntity);
            _context.Security.CreateSecurityEntity(grandChildEntity);

            // inspection
            var memEntity = _context.Security.GetSecurityEntity(rootId);
            Assert.AreEqual(0, memEntity.Level);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User1.Id, memEntity.OwnerId);
            var dbEntity = GetStoredSecurityEntity(_context, rootId);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User1.Id, dbEntity.OwnerId);

            memEntity = _context.Security.GetSecurityEntity(childId);
            Assert.AreEqual(1, memEntity.Level);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(_context, childId);
            Assert.AreEqual(rootId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);

            memEntity = _context.Security.GetSecurityEntity(grandChildId);
            Assert.AreEqual(2, memEntity.Level);
            Assert.AreEqual(childId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User3.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(_context, grandChildId);
            Assert.AreEqual(childId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User3.Id, dbEntity.OwnerId);
        }
        [TestMethod]
        public void EF6_Structure_CreateChildEntityChainByIds()
        {
            // Preparing
            _context = Start();

            var rootId = Id("E101");
            var childId = Id("E102");
            var grandChildId = Id("E103");

            //# calling the security component for creating an entity chain
            _context.Security.CreateSecurityEntity(rootId, default(int), TestUser.User1.Id);
            _context.Security.CreateSecurityEntity(childId, rootId, TestUser.User2.Id);
            _context.Security.CreateSecurityEntity(grandChildId, childId, TestUser.User3.Id);

            // inspection
            var db = new PrivateObject(_context.Security.DataProvider);
            var memEntity = _context.Security.GetSecurityEntity(rootId);
            Assert.AreEqual(0, memEntity.Level);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User1.Id, memEntity.OwnerId);
            var dbEntity = GetStoredSecurityEntity(_context, rootId);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User1.Id, dbEntity.OwnerId);

            memEntity = _context.Security.GetSecurityEntity(childId);
            Assert.AreEqual(1, memEntity.Level);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(rootId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(_context, childId);
            Assert.AreEqual(rootId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);

            memEntity = _context.Security.GetSecurityEntity(grandChildId);
            Assert.AreEqual(2, memEntity.Level);
            Assert.AreEqual(childId, memEntity.Parent.Id);
            Assert.AreEqual(TestUser.User3.Id, memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(_context, grandChildId);
            Assert.AreEqual(childId, dbEntity.ParentId);
            Assert.AreEqual(TestUser.User3.Id, dbEntity.OwnerId);
        }
        [TestMethod]
        public void EF6_Structure_EntityLevel()
        {
            // Preparing
            _context = Start();

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
            _context.Security.CreateSecurityEntity(rootEntity);
            _context.Security.CreateSecurityEntity(childEntity1);
            _context.Security.CreateSecurityEntity(childEntity2);
            _context.Security.CreateSecurityEntity(grandChildEntity1);
            _context.Security.CreateSecurityEntity(grandChildEntity2);
            _context.Security.CreateSecurityEntity(grandChildEntity3);

            // checking target object structure in memory
            var entity = _context.Security.GetSecurityEntity(rootId);
            Assert.AreEqual(0, entity.Level);
            entity = _context.Security.GetSecurityEntity(childId1);
            Assert.AreEqual(1, entity.Level);
            entity = _context.Security.GetSecurityEntity(childId2);
            Assert.AreEqual(1, entity.Level);
            entity = _context.Security.GetSecurityEntity(grandChildId1);
            Assert.AreEqual(2, entity.Level);
            entity = _context.Security.GetSecurityEntity(grandChildId2);
            Assert.AreEqual(2, entity.Level);
            entity = _context.Security.GetSecurityEntity(grandChildId3);
            Assert.AreEqual(2, entity.Level);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EF6_Structure_CreateSecurityEntity_invalidId()
        {
            _context = Start();
            //# calling the security component
            _context.Security.CreateSecurityEntity(default(int), default(int), default(int));
        }
        [TestMethod]
        public void EF6_Structure_CreateSecurityEntity_existing()
        {
            _context = Start();
            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, Parent = null };
            _context.Security.CreateSecurityEntity(entity);
            entity.OwnerId = TestUser.User2.Id;
            _context.Security.CreateSecurityEntity(entity);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF6_Structure_CreateSecurityEntity_missingParent()
        {
            _context = Start();
            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, ParentId = int.MaxValue };
            _context.Security.CreateSecurityEntity(entity);
        }

        [TestMethod]
        public void EF6_Structure_High_DeleteEntity()
        {
            // Preparing
            _context = Start();

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
                _context.Security.CreateSecurityEntity(rootEntity);
                _context.Security.CreateSecurityEntity(childEntity1);
                _context.Security.CreateSecurityEntity(childEntity2);
                _context.Security.CreateSecurityEntity(grandChildEntity1);
                _context.Security.CreateSecurityEntity(grandChildEntity2);
                _context.Security.CreateSecurityEntity(grandChildEntity3);
            }
            catch
            {
                // ignored
            }

            //# Deleting an entity that has two children
            _context.Security.DeleteEntity(childEntity1);

            // inspection
            Assert.IsNotNull(_context.Security.GetSecurityEntity(rootId));
            Assert.IsNull(_context.Security.GetSecurityEntity(childId1));
            Assert.IsNotNull(_context.Security.GetSecurityEntity(childId2));
            Assert.IsNull(_context.Security.GetSecurityEntity(grandChildId1));
            Assert.IsNull(_context.Security.GetSecurityEntity(grandChildId2));
            Assert.IsNotNull(_context.Security.GetSecurityEntity(grandChildId3));

            Assert.IsNotNull(GetStoredSecurityEntity(_context, rootId));
            Assert.IsNull(GetStoredSecurityEntity(_context, childId1));
            Assert.IsNotNull(GetStoredSecurityEntity(_context, childId2));
            Assert.IsNull(GetStoredSecurityEntity(_context, grandChildId1));
            Assert.IsNull(GetStoredSecurityEntity(_context, grandChildId2));
            Assert.IsNotNull(GetStoredSecurityEntity(_context, grandChildId3));
        }
        [TestMethod]
        public void EF6_Structure_Low_DeleteEntity()
        {
            // Preparing
            _context = Start();

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
                _context.Security.CreateSecurityEntity(rootEntity);
                _context.Security.CreateSecurityEntity(childEntity1);
                _context.Security.CreateSecurityEntity(childEntity2);
                _context.Security.CreateSecurityEntity(grandChildEntity1);
                _context.Security.CreateSecurityEntity(grandChildEntity2);
                _context.Security.CreateSecurityEntity(grandChildEntity3);
            }
            catch
            {
                // ignored
            }

            //# Deleting an entity that has two children

            _context.Security.DeleteEntity(childId1);

            // inspection
            Assert.IsNotNull(_context.Security.GetSecurityEntity(rootId));
            Assert.IsNull(_context.Security.GetSecurityEntity(childId1));
            Assert.IsNotNull(_context.Security.GetSecurityEntity(childId2));
            Assert.IsNull(_context.Security.GetSecurityEntity(grandChildId1));
            Assert.IsNull(_context.Security.GetSecurityEntity(grandChildId2));
            Assert.IsNotNull(_context.Security.GetSecurityEntity(grandChildId3));

            Assert.IsNotNull(GetStoredSecurityEntity(_context, rootId));
            Assert.IsNull(GetStoredSecurityEntity(_context, childId1));
            Assert.IsNotNull(GetStoredSecurityEntity(_context, childId2));
            Assert.IsNull(GetStoredSecurityEntity(_context, grandChildId1));
            Assert.IsNull(GetStoredSecurityEntity(_context, grandChildId2));
            Assert.IsNotNull(GetStoredSecurityEntity(_context, grandChildId3));

        }
        [TestMethod]
        public void EF6_Structure_DeletingMissingEntityDoesNotThrows()
        {
            _context = Start();

            _context.Security.DeleteEntity(int.MaxValue);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EF6_Structure_DeleteEntity_invalidId()
        {
            _context = Start();

            _context.Security.DeleteEntity(default(int));
        }



        [TestMethod]
        public void EF6_Structure_ModifyEntity()
        {
            _context = Start();

            var id = Id("E101");
            var entity = new TestEntity
            {
                Id = id,
                OwnerId = TestUser.User1.Id,
                Parent = null
            };

            try { _context.Security.CreateSecurityEntity(entity); }
            catch
            {
                // ignored
            }

            entity.OwnerId = TestUser.User2.Id;

            //# calling the security component for modifying the entity data
            _context.Security.ModifyEntity(entity);

            var memEntity = _context.Security.GetSecurityEntity(id);
            Assert.AreEqual(id, memEntity.Id);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            var dbEntity = GetStoredSecurityEntity(_context, id);
            Assert.AreEqual(id, dbEntity.Id);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);


            //# calling the security component for clearing the entity's owner
            entity.OwnerId = default(int);
            _context.Security.ModifyEntity(entity);

            memEntity = _context.Security.GetSecurityEntity(id);
            Assert.AreEqual(default(int), memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(_context, id);
            Assert.AreEqual(default(int), dbEntity.OwnerId);

        }
        [TestMethod]
        public void EF6_Structure_ModifyEntityOwner()
        {
            _context = Start();

            var id = Id("E101");

            try { _context.Security.CreateSecurityEntity(id, default(int), TestUser.User1.Id); }
            catch
            {
                // ignored
            }

            //# calling the security component for modifying the entity's owner
            _context.Security.ModifyEntityOwner(id, TestUser.User2.Id);

            var memEntity = _context.Security.GetSecurityEntity(id);
            Assert.AreEqual(id, memEntity.Id);
            Assert.IsNull(memEntity.Parent);
            Assert.AreEqual(TestUser.User2.Id, memEntity.OwnerId);
            var dbEntity = GetStoredSecurityEntity(_context, id);
            Assert.AreEqual(id, dbEntity.Id);
            Assert.AreEqual(default(int), dbEntity.ParentId);
            Assert.AreEqual(TestUser.User2.Id, dbEntity.OwnerId);

            //# calling the security component for clearing the entity's owner
            _context.Security.ModifyEntityOwner(id, default(int));

            memEntity = _context.Security.GetSecurityEntity(id);
            Assert.AreEqual(default(int), memEntity.OwnerId);
            dbEntity = GetStoredSecurityEntity(_context, id);
            Assert.AreEqual(default(int), dbEntity.OwnerId);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EF6_Structure_ModifyEntityOwner_invalidId()
        {
            _context = Start();

            _context.Security.ModifyEntityOwner(default(int), TestUser.User2.Id);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EF6_Structure_ModifyEntity_invalidId()
        {
            _context = Start();

            var entity = new TestEntity { Id = default(int), OwnerId = TestUser.User1.Id, Parent = null };
            _context.Security.ModifyEntity(entity);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF6_Structure_ModifyigEntity_missing()
        {
            _context = Start();

            var entity = new TestEntity { Id = Id("E101"), OwnerId = TestUser.User1.Id, Parent = null };
            _context.Security.ModifyEntity(entity);
        }



        [TestMethod]
        public void EF6_Structure_MoveEntity()
        {
            CreateStructureForMoveTests(out var root, out var source, out var target, out var child1, out var child2);

            //#
            _context.Security.MoveEntity(source, target);

            // check in database
            var movedDbEntity = GetStoredSecurityEntity(_context, source.Id);
            var targetDbEntity = GetStoredSecurityEntity(_context, target.Id);
            var child1DbEntity = GetStoredSecurityEntity(_context, child1.Id);
            var child2DbEntity = GetStoredSecurityEntity(_context, child2.Id);
            Assert.AreEqual(movedDbEntity.ParentId, targetDbEntity.Id);

            // check in memory
            var movedEntity = _context.Security.GetSecurityEntity(source.Id);
            var targetEntity = _context.Security.GetSecurityEntity(target.Id);
            var child1Entity = _context.Security.GetSecurityEntity(child1.Id);
            var child2Entity = _context.Security.GetSecurityEntity(child2.Id);

            Assert.AreEqual(targetEntity.Id, movedEntity.Parent.Id);
            Assert.AreEqual(child1Entity.GetFirstAclId(), child1Entity.Id);
            Assert.AreEqual(child2Entity.GetFirstAclId(), target.Id);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EF6_Structure_MoveEntity_InvalidSource()
        {
            CreateStructureForMoveTests(out var root, out var source, out var target, out var child1, out var child2);
            source.Id = default(int);
            _context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EF6_Structure_MoveEntity_InvalidTarget()
        {
            CreateStructureForMoveTests(out var root, out var source, out var target, out var child1, out var child2);
            target.Id = default(int);
            _context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF6_Structure_MoveEntity_MissingSource()
        {
            CreateStructureForMoveTests(out var root, out var source, out var target, out var child1, out var child2);
            source.Id = Id("E101");
            _context.Security.MoveEntity(source, target);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF6_Structure_MoveEntity_MissingTarget()
        {
            CreateStructureForMoveTests(out var root, out var source, out var target, out var child1, out var child2);
            target.Id = Id("E101");
            _context.Security.MoveEntity(source, target);
        }

        private void CreateStructureForMoveTests(out TestEntity root, out TestEntity source, out TestEntity target, out TestEntity child1, out TestEntity child2)
        {
            _context = Start();

            root = new TestEntity { Id = Id("E201"), OwnerId = TestUser.User1.Id, Parent = null };
            source = new TestEntity { Id = Id("E202"), OwnerId = TestUser.User1.Id, Parent = root };
            target = new TestEntity { Id = Id("E203"), OwnerId = TestUser.User1.Id, Parent = root };
            child1 = new TestEntity { Id = Id("E204"), OwnerId = TestUser.User1.Id, Parent = source };
            child2 = new TestEntity { Id = Id("E205"), OwnerId = TestUser.User1.Id, Parent = source };

            // Calling the security component for creating entity tree
            //context.DataProvider._DeleteAllSecurityEntities();
            _context.Security.CreateSecurityEntity(root);
            _context.Security.CreateSecurityEntity(source);
            _context.Security.CreateSecurityEntity(target);
            _context.Security.CreateSecurityEntity(child1);
            _context.Security.CreateSecurityEntity(child2);

            _context.Security.CreateAclEditor()
                .Allow(root.Id, 1001, false, PermissionType.Open)
                .Allow(target.Id, 1002, false, PermissionType.Open)
                .Allow(child1.Id, 1003, false, PermissionType.Open)
                .Apply();
        }




        [TestMethod]
        public void EF6_Structure_High_BreakInheritance()
        {
            CreateStructureForInheritanceTests(out var ids);

            //# calling the security component for breaking permission inheritance
            _context.Security.BreakInheritance(new TestEntity { Id = ids[1], ParentId = ids[0] });

            // inspection
            var dbEntity = GetStoredSecurityEntity(_context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            var entity = _context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void EF6_Structure_Low_BreakInheritance()
        {
            CreateStructureForInheritanceTests(out var ids);

            //# calling the security component for breaking permission inheritance
            _context.Security.BreakInheritance(ids[1]);

            // inspection
            var dbEntity = GetStoredSecurityEntity(_context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            var entity = _context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void EF6_Structure_BreakInheritance_Breaked()
        {
            CreateStructureForInheritanceTests(out var ids);

            _context.Security.BreakInheritance(ids[1]);
            // valid but ineffective
            _context.Security.BreakInheritance(ids[1]);

            // inspection
            var dbEntity = GetStoredSecurityEntity(_context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            var entity = _context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF6_Structure_BreakInheritance_Invalid()
        {
            _context = Start();

            _context.Security.BreakInheritance(default(int));
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF6_Structure_BreakInheritance_Missing()
        {
            _context = Start();

            _context.Security.BreakInheritance(int.MaxValue);
        }

        [TestMethod]
        public void EF6_Structure_High_UnbreakInheritance()
        {
            CreateStructureForInheritanceTests(out var ids);
            _context.Security.BreakInheritance(ids[1]);

            var dbEntity = GetStoredSecurityEntity(_context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            var entity = _context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);

            //# calling the security component for restoring breaked permission inheritance
            _context.Security.UnbreakInheritance(new TestEntity { Id = ids[1], ParentId = ids[0] });

            // inspection
            dbEntity = GetStoredSecurityEntity(_context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[1]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            entity = _context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[1]);
            Assert.IsTrue(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void EF6_Structure_Low_UnbreakInheritance()
        {
            CreateStructureForInheritanceTests(out var ids);
            _context.Security.BreakInheritance(ids[1]);

            var dbEntity = GetStoredSecurityEntity(_context, ids[1]);
            Assert.IsFalse(dbEntity.IsInherited);
            var entity = _context.Security.GetSecurityEntity(ids[1]);
            Assert.IsFalse(entity.IsInherited);

            //# calling the security component for restoring breaked permission inheritance
            _context.Security.UnbreakInheritance(ids[1]);

            // inspection
            dbEntity = GetStoredSecurityEntity(_context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[1]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            entity = _context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[1]);
            Assert.IsTrue(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        public void EF6_Structure_UnbreakInheritance_Unbreaked()
        {
            CreateStructureForInheritanceTests(out var ids);
            _context.Security.BreakInheritance(ids[1]);

            //#
            _context.Security.UnbreakInheritance(ids[1]);
            //# valid but ineffective
            _context.Security.UnbreakInheritance(ids[1]);

            // inspection
            var dbEntity = GetStoredSecurityEntity(_context, ids[0]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[1]);
            Assert.IsTrue(dbEntity.IsInherited);
            dbEntity = GetStoredSecurityEntity(_context, ids[2]);
            Assert.IsTrue(dbEntity.IsInherited);

            var entity = _context.Security.GetSecurityEntity(ids[0]);
            Assert.IsTrue(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[1]);
            Assert.IsTrue(entity.IsInherited);
            entity = _context.Security.GetSecurityEntity(ids[2]);
            Assert.IsTrue(entity.IsInherited);
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF6_Structure_UnbreakInheritance_Invalid()
        {
            _context = Start();

            _context.Security.UnbreakInheritance(default(int));
        }
        [TestMethod]
        [ExpectedException(typeof(EntityNotFoundException))]
        public void EF6_Structure_UnbreakInheritance_Missing()
        {
            _context = Start();

            _context.Security.UnbreakInheritance(int.MaxValue);
        }




        private void CreateStructureForInheritanceTests(out int[] chain)
        {
            _context = Start();

            var rootEntity = new TestEntity { Id = Id("E251"), OwnerId = TestUser.User1.Id, Parent = null };
            var childEntity = new TestEntity { Id = Id("E252"), OwnerId = TestUser.User1.Id, Parent = rootEntity };
            var grandChildEntity = new TestEntity { Id = Id("E253"), OwnerId = TestUser.User1.Id, Parent = childEntity };

            try
            {
                _context.Security.CreateSecurityEntity(rootEntity);
                _context.Security.CreateSecurityEntity(childEntity);
                _context.Security.CreateSecurityEntity(grandChildEntity);
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
