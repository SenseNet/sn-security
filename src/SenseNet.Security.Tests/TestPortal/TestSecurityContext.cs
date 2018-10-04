using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SenseNet.Security.Tests.TestPortal
{
    public class TestSecurityContext : SecurityContext
    {
        public TestSecurityContext(ISecurityUser currentUser) : base(currentUser) { }

        public static new void StartTheSystem(SecurityConfiguration configuration)
        {
            SecurityContext.StartTheSystem(configuration);
            _generalContext = new TestSecurityContext(SystemUser);
        }

        /*********************** ACL API **********************/
        public new AclEditor CreateAclEditor(EntryType entryType = EntryType.Normal)
        {
            return base.CreateAclEditor(entryType);
        }
        public new AccessControlList GetAcl(int entityId)
        {
            return base.GetAcl(entityId);
        }
        public new List<AceInfo> GetEffectiveEntries(int entityId, IEnumerable<int> relatedIdentities = null)
        {
            return base.GetEffectiveEntries(entityId, relatedIdentities);
        }
        public new List<AceInfo> GetExplicitEntries(int entityId, IEnumerable<int> relatedIdentities = null)
        {
            return base.GetExplicitEntries(entityId, relatedIdentities);
        }

        /*********************** Low level evaluator API **********************/
        public new void AssertPermission(int entityId, params PermissionTypeBase[] permissions)
        {
            base.AssertPermission(entityId, permissions);
        }
        public new void AssertSubtreePermission(int entityId, params PermissionTypeBase[] permissions)
        {
            base.AssertSubtreePermission(entityId, permissions);
        }
        public new bool HasPermission(int entityId, params PermissionTypeBase[] permissions)
        {
            return base.HasPermission(entityId, permissions);
        }
        public new bool HasSubtreePermission(int entityId, params PermissionTypeBase[] permissions)
        {
            return base.HasSubtreePermission(entityId, permissions);
        }
        public new PermissionValue GetPermission(int entityId, params PermissionTypeBase[] permissions)
        {
            return base.GetPermission(entityId, permissions);
        }
        public new PermissionValue GetSubtreePermission(int entityId, params PermissionTypeBase[] permissions)
        {
            return base.GetSubtreePermission(entityId, permissions);
        }

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
        public new void CreateSecurityEntity(int entityId, int parentEntityId, int ownerId)
        {
            base.CreateSecurityEntity(entityId, parentEntityId, ownerId);
        }
        public new void ModifyEntityOwner(int entityId, int ownerId)
        {
            base.ModifyEntityOwner(entityId, ownerId);
        }
        public new void DeleteEntity(int entityId)
        {
            base.DeleteEntity(entityId);
        }
        public new void MoveEntity(int sourceId, int targetId)
        {
            base.MoveEntity(sourceId, targetId);
        }
        public void BreakInheritance(int entityId, bool convertToExplicit = true)
        {
            AclEditor.Create(this).BreakInheritance(entityId, convertToExplicit).Apply();
        }
        public void UnbreakInheritance(int entityId, bool normalize = false)
        {
            AclEditor.Create(this).UnbreakInheritance(entityId, normalize).Apply();
        }
        public new bool IsEntityInherited(int entityId)
        {
            return base.IsEntityInherited(entityId);
        }
        public new bool IsEntityExist(int entityId)
        {
            return base.IsEntityExist(entityId);
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
            AclEditor.Create(this).BreakInheritance(entity.Id, convertToExplicit).Apply();
        }
        public void UnbreakInheritance(TestEntity entity, bool normalize = false)
        {
            AclEditor.Create(this).UnbreakInheritance(entity.Id, normalize).Apply();
        }
        public bool IsEntityInherited(TestEntity entity)
        {
            return base.IsEntityInherited(entity.Id);
        }

        /*********************** Public permission query API **********************/
        public new IEnumerable<int> GetRelatedIdentities(int entityId, PermissionLevel level)
        {
            return base.GetRelatedIdentities(entityId, level);
        }
        public new Dictionary<PermissionTypeBase, int> GetRelatedPermissions(int entityId, PermissionLevel level, bool explicitOnly, int identityId, Func<int, bool> isEnabled)
        {
            return base.GetRelatedPermissions(entityId, level, explicitOnly, identityId, isEnabled);
        }
        public new IEnumerable<int> GetRelatedEntities(int entityId, PermissionLevel level, bool explicitOnly, int identityId, IEnumerable<PermissionTypeBase> permissions)
        {
            return base.GetRelatedEntities(entityId, level, explicitOnly, identityId, permissions);
        }
        public new IEnumerable<int> GetRelatedIdentities(int entityId, PermissionLevel level, IEnumerable<PermissionTypeBase> permissions)
        {
            return base.GetRelatedIdentities(entityId, level, permissions);
        }
        public new IEnumerable<int> GetRelatedEntitiesOneLevel(int entityId, PermissionLevel level, int identityId, IEnumerable<PermissionTypeBase> permissions)
        {
            return base.GetRelatedEntitiesOneLevel(entityId, level, identityId, permissions);
        }
        public new IEnumerable<int> GetAllowedUsers(int entityId, IEnumerable<PermissionTypeBase> permissions)
        {
            return base.GetAllowedUsers(entityId, permissions);
        }
        public new IEnumerable<int> GetParentGroups(int entityId, bool directOnly)
        {
            return base.GetParentGroups(entityId, directOnly);
        }

        /*********************** Membership API (low level only) **********************/
        public new int[] GetFlattenedGroups()
        {
            return base.GetFlattenedGroups();
        }
        public new List<int> GetGroups()
        {
            return base.GetGroups();
        }
        public new List<int> GetGroupsWithOwnership(int entityId)
        {
            return base.GetGroupsWithOwnership(entityId);
        }

        public new bool IsInGroup(int memberId, int groupId)
        {
            return base.IsInGroup(memberId, groupId);
        }

        public new void AddMembersToSecurityGroup(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, IEnumerable<int> parentGroups = null)
        {
            base.AddMembersToSecurityGroup(groupId, userMembers, groupMembers, parentGroups);
        }
        public new void RemoveMembersFromSecurityGroup(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, IEnumerable<int> parentGroups = null)
        {
            base.RemoveMembersFromSecurityGroup(groupId, userMembers, groupMembers, parentGroups);
        }

        public new void AddGroupsToSecurityGroup(int groupId, IEnumerable<int> groupMembers)
        {
            base.AddGroupsToSecurityGroup(groupId, groupMembers);
        }
        public new void AddGroupToSecurityGroups(int groupId, IEnumerable<int> parentGroups)
        {
            base.AddGroupToSecurityGroups(groupId, parentGroups);
        }
        public new void RemoveGroupsFromSecurityGroup(int groupId, IEnumerable<int> groupMembers)
        {
            base.RemoveGroupsFromSecurityGroup(groupId, groupMembers);
        }
        public new void RemoveGroupFromSecurityGroups(int groupId, IEnumerable<int> parentGroups)
        {
            base.RemoveGroupFromSecurityGroups(groupId, parentGroups);
        }
        public new void AddUsersToSecurityGroup(int groupId, IEnumerable<int> userMembers)
        {
            base.AddUsersToSecurityGroup(groupId, userMembers);
        }
        public new void AddUserToSecurityGroups(int userId, IEnumerable<int> parentGroups)
        {
            base.AddUserToSecurityGroups(userId, parentGroups);
        }
        public new void RemoveUserFromSecurityGroups(int userId, IEnumerable<int> parentGroups)
        {
            base.RemoveUserFromSecurityGroups(userId, parentGroups);
        }
        public new void RemoveUsersFromSecurityGroup(int groupId, IEnumerable<int> userMembers)
        {
            base.RemoveUsersFromSecurityGroup(groupId, userMembers);
        }

        public new void DeleteSecurityGroup(int groupId)
        {
            base.DeleteSecurityGroup(groupId);
        }
        public new void DeleteUser(int userId)
        {
            base.DeleteUser(userId);
        }
        public new void DeleteIdentity(int id)
        {
            base.DeleteIdentity(id);
        }
        public new void DeleteIdentities(IEnumerable<int> ids)
        {
            base.DeleteIdentities(ids);
        }

        /***************** General context for built in system user ***************/
        private static SecurityContext _generalContext;
        internal static new SecurityContext General
        {
            get { return _generalContext; }
        }
    }
}
