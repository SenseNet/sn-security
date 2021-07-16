using System;
using System.Collections.Generic;

namespace SenseNet.Security.Tests.TestPortal
{
    public class TestSecurityContext : SecurityContext
    {
        private static SecuritySystem _securitySystem;

        public TestSecurityContext(ISecurityUser currentUser) : base(currentUser, _securitySystem) { }

        public static SecuritySystem StartTheSystem(SecurityConfiguration configuration)
        {
            _securitySystem = SecuritySystem.StartTheSystem(configuration);
            General = new TestSecurityContext(_securitySystem.SystemUser);
            return _securitySystem;
        }

        public ISecurityDataProvider GetDataProvider() => SecuritySystem.DataProvider;

        /*********************** High level evaluator API **********************/
        public void AssertPermission(TestEntity entity, params PermissionTypeBase[] permissions)
        {
            base.AssertPermission(entity.Id, permissions);
        }
        public void AssertSubtreePermission(TestEntity entity, params PermissionTypeBase[] permissions)
        {
            base.AssertSubtreePermission(entity.Id, permissions);
        }
        public bool HasPermission(TestEntity entity, params PermissionTypeBase[] permissions)
        {
            return base.HasPermission(entity.Id, permissions);
        }
        public bool HasSubtreePermission(TestEntity entity, params PermissionTypeBase[] permissions)
        {
            return base.HasSubtreePermission(entity.Id, permissions);
        }

        /*********************** Low level structure API **********************/
        public void BreakInheritance(int entityId, bool convertToExplicit = true)
        {
            var categories = convertToExplicit ? new[] { EntryType.Normal } : new EntryType[0];
            new AclEditor(this).BreakInheritance(entityId, categories).Apply();
        }
        public void UndoBreakInheritance(int entityId, bool normalize = false)
        {
            var categories = normalize ? new[] {EntryType.Normal} : new EntryType[0];
            new AclEditor(this).UnBreakInheritance(entityId, categories).Apply();
        }

        /*********************** High level structure API **********************/
        public void CreateSecurityEntity(TestEntity entity)
        {
            base.CreateSecurityEntity(entity.Id, entity.ParentId, entity.OwnerId);
        }
        public void ModifyEntity(TestEntity entity)
        {
            base.ModifyEntityOwner(entity.Id, entity.OwnerId);
        }
        public void DeleteEntity(TestEntity entity)
        {
            base.DeleteEntity(entity.Id);
        }
        public void MoveEntity(TestEntity source, TestEntity target)
        {
            base.MoveEntity(source.Id, target.Id);
        }
        public void BreakInheritance(TestEntity entity, bool convertToExplicit = true)
        {
            var categories = convertToExplicit ? new[] { EntryType.Normal } : new EntryType[0];
            new AclEditor(this).BreakInheritance(entity.Id, categories).Apply();
        }
        public void UndoBreakInheritance(TestEntity entity, bool normalize = false)
        {
            var categories = normalize ? new[] { EntryType.Normal } : new EntryType[0];
            new AclEditor(this).UnBreakInheritance(entity.Id, categories).Apply();
        }
        public bool IsEntityInherited(TestEntity entity)
        {
            return base.IsEntityInherited(entity.Id);
        }

        /***************** General context for built in system user ***************/
        internal static SecurityContext General { get; private set; }
    }
}
