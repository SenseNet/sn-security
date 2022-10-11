using System;
using System.Collections.Generic;
using System.Linq;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;
using SenseNet.Diagnostics;

namespace SenseNet.Security
{
    /// <summary>
    /// The front-end object of the SenseNet.Security component.
    /// Provides an environment for querying and editing security related data.
    /// </summary>
    public partial class SecurityContext
    {
        public SecuritySystem SecuritySystem { get; }

        /// <summary>
        /// Gets the associated user instance.
        /// </summary>
        public ISecurityUser CurrentUser { get; }

        internal PermissionEvaluator Evaluator { get; }

        private readonly PermissionQuery _permissionQuery;

        /***************************** Context **************************/

        /// <summary>
        /// Creates a new instance of the SecurityContext using the passed user instance and the SecuritySystem.
        /// </summary>
        public SecurityContext(ISecurityUser currentUser, SecuritySystem securitySystem)
        {
            CurrentUser = currentUser;
            SecuritySystem = securitySystem;
            Evaluator = new PermissionEvaluator(this);
            _permissionQuery = SecuritySystem.PermissionQuery;
        }

        /*********************** ACL API **********************/
        /// <summary>
        /// Creates a new instance of the AclEditor class for modifying access control data.
        /// Editor handles only one type of entries. Default EntryType is Normal.
        /// </summary>
        public virtual AclEditor CreateAclEditor(EntryType entryType = EntryType.Normal)
        {
            return new AclEditor(this, entryType);
        }
        /// <summary>
        /// Returns the AccessControlList of the passed entity to help building a rich GUI for modifications.
        /// The entity must exist. Entity resolution can compensate the entity integrity error.
        /// </summary>
        public virtual AccessControlList GetAcl(int entityId, EntryType entryType = EntryType.Normal)
        {
            return SecuritySystem.EntityManager.GetAccessControlList(entityId, entryType);
        }

        /// <summary>
        /// Returns an aggregated effective entries of the requested entity.
        /// Inheritance information is not included.
        /// The entity must exist. Entity resolution can compensate the entity integrity error.
        /// </summary>
        /// <param name="entityId">Id of the entity.</param>
        /// <param name="relatedIdentities">Optional, can be null.
        /// If it is provided, the output will be filtered for the related identities.
        /// Empty collection means nobody, so in case of passing empty,
        /// the method will return an empty list.</param>
        /// <param name="entryType">Optional filter parameter.</param>
        public virtual List<AceInfo> GetEffectiveEntries(int entityId, IEnumerable<int> relatedIdentities = null, EntryType? entryType = null)
        {
            return Evaluator.GetEffectiveEntries(entityId, relatedIdentities, entryType);
        }
        /// <summary>
        /// Returns the explicit entries of the requested entity.
        /// Inheritance information is not included.
        /// The entity must exist. Entity resolution can compensate the entity integrity error.
        /// </summary>
        /// <param name="entityId">Id of the entity.</param>
        /// <param name="relatedIdentities">Optional, can be null.
        /// If it is provided, the output will be filtered for the related identities.
        /// Empty collection means nobody, so in case of passing empty,
        /// the method will return an empty list.</param>
        /// <param name="entryType">Optional filter parameter.</param>
        public virtual List<AceInfo> GetExplicitEntries(int entityId, IEnumerable<int> relatedIdentities = null, EntryType? entryType = null)
        {
            return Evaluator.GetExplicitEntries(entityId, relatedIdentities, entryType);
        }

        // for tests
        internal AclInfo GetAclInfo(int finalEntityId, bool throwOnError = false)
        {
            var entity = SecuritySystem.EntityManager.GetEntity(finalEntityId, throwOnError);
            var acl = entity?.Acl;
            return acl;
        }
        // for tests
        internal void SetAcls(IEnumerable<AclInfo> acls, List<int> breaks, List<int> undoBreaks)
        {
            if (acls == null)
                throw new ArgumentNullException(nameof(acls));
            // ReSharper disable once PossibleMultipleEnumeration
            if (!acls.Any())
                return;
            // ReSharper disable once PossibleMultipleEnumeration
            var activity = new SetAclActivity(acls, breaks, undoBreaks);
            activity.Execute(this);
        }

        /*********************** Evaluator API **********************/
        /// <summary>
        /// If one or more passed permissions are not allowed (undefined or denied)
        /// on the passed entity for the current user,
        /// an <see cref="AccessDeniedException"/> will be thrown.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        /// <param name="permissions">Set of related permissions. Cannot be null.
        /// Empty set means "allowed nothing" so SenseNetSecurityException will be thrown.</param>
        public virtual void AssertPermission(int entityId, params PermissionTypeBase[] permissions)
        {
            if (!HasPermission(entityId, permissions))
                throw new AccessDeniedException(null, null, entityId, null, permissions);
        }
        /// <summary>
        /// If one or more passed permissions are not allowed (undefined or denied)
        /// on the passed entity for the current user,
        /// an <see cref="AccessDeniedException"/> will be thrown.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        /// <param name="entryType">Permission entry filter. Only these types of entries will be taken into account in the evaluation process.</param>
        /// <param name="permissions">Set of related permissions. Cannot be null.
        /// Empty set means "allowed nothing" so SenseNetSecurityException will be thrown.</param>
        public virtual void AssertPermission(int entityId, EntryType entryType, params PermissionTypeBase[] permissions)
        {
            if (!HasPermission(entityId, entryType, permissions))
                throw new AccessDeniedException(null, null, entityId, null, permissions);
        }
        /// <summary>
        /// If one or more passed permissions are not allowed (undefined or denied)
        /// on every entity in the whole subtree of the passed entity for the current user,
        /// an <see cref="AccessDeniedException"/> will be thrown.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        /// <param name="permissions">Set of related permissions. Cannot be null.
        /// Empty set means "allowed nothing" so AccessDeniedException will be thrown.</param>
        public virtual void AssertSubtreePermission(int entityId, params PermissionTypeBase[] permissions)
        {
            if (!HasSubtreePermission(entityId, permissions))
                throw new AccessDeniedException(null, null, entityId, null, permissions);
        }
        /// <summary>
        /// Returns true if all passed permissions are allowed on the passed entity for the current user.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        /// <param name="permissions">Set of related permissions. Cannot be null. Empty set means "allowed nothing".</param>
        public virtual bool HasPermission(int entityId, params PermissionTypeBase[] permissions)
        {
            return Evaluator.HasPermission(CurrentUser.Id, entityId, GetOwnerId(entityId), permissions);
        }
        /// <summary>
        /// Returns true if all passed permissions are allowed on the passed entity for the current user.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        /// <param name="entryType">Permission entry filter. Only these types of entries will be taken into account in the evaluation process.</param>
        /// <param name="permissions">Set of related permissions. Cannot be null. Empty set means "allowed nothing".</param>
        public virtual bool HasPermission(int entityId, EntryType entryType, params PermissionTypeBase[] permissions)
        {
            return Evaluator.HasPermission(CurrentUser.Id, entityId, GetOwnerId(entityId), null, permissions);
        }
        /// <summary>
        /// Returns true if all passed permissions are allowed for the current user on every entity in the whole subtree of the passed entity.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        /// <param name="permissions">Set of related permissions. Cannot be null. Empty set means "allowed nothing".</param>
        public virtual bool HasSubtreePermission(int entityId, params PermissionTypeBase[] permissions)
        {
            return Evaluator.HasSubTreePermission(CurrentUser.Id, entityId, GetOwnerId(entityId), permissions);
        }
        /// <summary>
        /// Returns an aggregated permission value by all passed permissions for the current user on the passed entity.
        /// Value is Denied if there is at least one denied among the passed permissions,
        ///   Undefined if there is an undefined and there is no denied among the passed permissions,
        ///   Allowed if every passed permission is allowed.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        /// <param name="permissions">Set of related permissions. Cannot be null. Empty set means "allowed nothing".</param>
        public virtual PermissionValue GetPermission(int entityId, params PermissionTypeBase[] permissions)
        {
            return Evaluator.GetPermission(CurrentUser.Id, entityId, GetOwnerId(entityId), permissions);
        }
        /// <summary>
        /// Returns an aggregated permission value by all passed permissions for the current user on the passed entity.
        /// Value is Denied if there is at least one denied among the passed permissions,
        ///   Undefined if there is an undefined and there is no denied among the passed permissions,
        ///   Allowed if every passed permission is allowed.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        /// <param name="entryType">Permission entry filter. Only these types of entries will be taken into account in the evaluation process.</param>
        /// <param name="permissions">Set of related permissions. Cannot be null. Empty set means "allowed nothing".</param>
        public virtual PermissionValue GetPermission(int entityId, EntryType entryType, params PermissionTypeBase[] permissions)
        {
            return Evaluator.GetPermission(CurrentUser.Id, entityId, GetOwnerId(entityId), entryType, permissions);
        }
        /// <summary>
        /// Returns an aggregated permission value by all passed permissions for the current user on every entity in whole subtree of the passed entity.
        /// Value is Denied if there is at least one denied among the passed permissions,
        ///   Undefined if there is an undefined and there is no denied among the passed permissions,
        ///   Allowed if every passed permission is allowed in the whole subtree of the entity.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        /// <param name="permissions">Set of related permissions. Cannot be null. Empty set means "allowed nothing".</param>
        public virtual PermissionValue GetSubtreePermission(int entityId, params PermissionTypeBase[] permissions)
        {
            return Evaluator.GetSubtreePermission(CurrentUser.Id, entityId, GetOwnerId(entityId), permissions);
        }

        /*********************** Structure API **********************/
        /// <summary>
        /// Creates a new entity. If it already exists, creation is skipped.
        /// Parent entity must exist. Parent resolution can compensate the entity integrity error.
        /// </summary>
        /// <param name="entityId">Id of the created entity. Cannot be 0.</param>
        /// <param name="parentEntityId">Id of the parent entity. Cannot be 0.</param>
        /// <param name="ownerId">Id of the entity's owner identity.</param>
        public virtual void CreateSecurityEntity(int entityId, int parentEntityId, int ownerId)
        {
            if (entityId == default)
                throw new ArgumentException("Id of the Entity cannot be " + default(int));
            var activity = new CreateSecurityEntityActivity(entityId, parentEntityId, ownerId);
            activity.Execute(this);
        }
        /// <summary>
        /// Changes the owner of the entity.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        /// <param name="ownerId">Id of the entity's owner identity.</param>
        public virtual void ModifyEntityOwner(int entityId, int ownerId)
        {
            if (entityId == default)
                throw new ArgumentException("Id of the Entity cannot be " + default(int));
            var activity = new ModifySecurityEntityOwnerActivity(entityId, ownerId);
            activity.Execute(this);
        }
        /// <summary>
        /// Deletes the entity, it's whole subtree and all related ACLs.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        public virtual void DeleteEntity(int entityId)
        {
            if (entityId == default)
                throw new ArgumentException("Id of the Entity cannot be " + default(int));
            var activity = new DeleteSecurityEntityActivity(entityId);
            activity.Execute(this);
        }
        /// <summary>
        /// Moves the entity and it's whole subtree, including the related ACLs.
        /// Source entity will be a child of the target entity.
        /// </summary>
        /// <param name="sourceId">Id of the source entity. Cannot be 0.</param>
        /// <param name="targetId">Id of the target entity that will contain the source. Cannot be 0.</param>
        public virtual void MoveEntity(int sourceId, int targetId)
        {
            if (sourceId == default)
                throw new ArgumentException("Id of the source Entity cannot be " + default(int));
            if (targetId == default)
                throw new ArgumentException("Id of the target Entity cannot be " + default(int));
            var activity = new MoveSecurityEntityActivity(sourceId, targetId);
            activity.Execute(this);
        }
        /// <summary>
        /// Returns false if the entity inherits permissions from it's parent.
        /// </summary>
        /// <param name="entityId">Id of the entity. Cannot be 0.</param>
        public virtual bool IsEntityInherited(int entityId)
        {
            if (entityId == default)
                throw new ArgumentException("Id of the Entity cannot be " + default(int));
            var entity = GetSecurityEntity(entityId, true);
            return entity.IsInherited;
        }
        /// <summary>
        /// Returns true if the entity exists in the security system.
        /// This method assumes that the entity exists and if not, executes a compensation algorithm
        /// that can repair a data integrity error (which may occur in case of a distributed system).
        /// The compensation works on two level:
        /// 1 - loads the entity from the security database to the memory.
        /// 2 - executes a callback to the host application (<see cref="IMissingEntityHandler"/>) and saves the entity if it is needed.
        /// </summary>
        public virtual bool IsEntityExist(int entityId)
        {
            return GetSecurityEntity(entityId) != null;
        }

        /*********************** Internal in memory entity structure **********************/
        internal SecurityEntity GetSecurityEntity(int entityId, bool throwError = false)
        {
            return SecuritySystem.EntityManager.GetEntity(entityId, throwError);
        }
        internal bool HasAncestorRelation(SecurityEntity entity1, SecurityEntity entity2)
        {
            return IsEntityInTree(entity1, entity2.Id) || IsEntityInTree(entity2, entity1.Id);
        }
        internal bool IsEntityInTree(SecurityEntity descendant, int ancestorId)
        {
            while (true)
            {
                if (descendant == null)
                    return false;
                if (descendant.Id == ancestorId)
                    return true;
                descendant = descendant.Parent;
            }
        }
        internal bool IsEntityInTree(int descendantId, int ancestorId)
        {
            // consider performance issue because of entity compensation
            while (true)
            {
                if (descendantId == ancestorId)
                    return true;
                var entity = GetSecurityEntity(descendantId);
                if (entity == null)
                    return false;
                descendantId = entity.Parent?.Id ?? default;
            }
        }
        internal int GetOwnerId(int entityId)
        {
            var entity = GetSecurityEntity(entityId, true);            

            return entity.OwnerId;
        }

        /*********************** Permission query API **********************/

        /// <summary>
        /// Collects all permission settings on the given entity and its subtree related to the specified user or group set.
        /// Output is grouped by permission types and can be filtered by the permission value.
        /// </summary>
        /// <param name="entityId">Id of the entity.</param>
        /// <param name="identities">Id of the groups or users.</param>
        /// <param name="includeRoot">Determines whether the provided root entity's permissions should be included in the result set.</param>
        public virtual Dictionary<PermissionTypeBase, int> GetExplicitPermissionsInSubtree(int entityId, int[] identities, bool includeRoot)
        {
            return _permissionQuery.GetExplicitPermissionsInSubtree(this, entityId, identities, includeRoot);
        }

        /// <summary>
        /// Returns all user and group ids that have any explicit permissions on the given entity or its subtree.
        /// </summary>
        /// <param name="entityId">Id of the entity.</param>
        /// <param name="level">Filtering by the permission value. It can be Allowed, Denied, AllowedOrDenied.</param>
        public virtual IEnumerable<int> GetRelatedIdentities(int entityId, PermissionLevel level)
        {
            return _permissionQuery.GetRelatedIdentities(this, entityId, level);
        }
        /// <summary>
        /// Collects all permission settings on the given entity and its subtree related to the specified user or group.
        /// Output is grouped by permission types and can be filtered by the permission value.
        /// </summary>
        /// <param name="entityId">Id of the entity.</param>
        /// <param name="level">Filtering by the permission value. It can be Allowed, Denied, AllowedOrDenied.</param>
        /// <param name="explicitOnly">Filter parameter for future use only. Allowed value is true.</param>
        /// <param name="identityId">Id of the group or user.</param>
        /// <param name="isEnabled">Filter method that can enable or disable any entity.</param>
        public virtual Dictionary<PermissionTypeBase, int> GetRelatedPermissions(int entityId, PermissionLevel level, bool explicitOnly, int identityId, Func<int, bool> isEnabled)
        {
           return _permissionQuery.GetRelatedPermissions(this, entityId, level, explicitOnly, identityId, isEnabled);
        }
        /// <summary>
        /// Returns all entity ids in the requested entity's subtree that have any permission setting
        /// filtered by permission value, user or group, and a permission mask
        /// </summary>
        /// <param name="entityId">Id of the entity.</param>
        /// <param name="level">Filtering by the permission value. It can be Allowed, Denied, AllowedOrDenied.</param>
        /// <param name="explicitOnly">Filter parameter for future use only. The currently allowed value is true.</param>
        /// <param name="identityId">Id of the group or user.</param>
        /// <param name="permissions">Only those entities appear in the output that have permission settings in connection with the given permissions.</param>
        public virtual IEnumerable<int> GetRelatedEntities(int entityId, PermissionLevel level, bool explicitOnly, int identityId, IEnumerable<PermissionTypeBase> permissions)
        {
            return _permissionQuery.GetRelatedEntities(this, entityId, level, explicitOnly, identityId, permissions);
        }

        /// <summary>
        /// Returns all user and group ids that have any explicit permission on the given entity and its subtree.
        /// </summary>
        /// <param name="entityId">Id of the entity.</param>
        /// <param name="level">Filtering by the permission value. It can be Allowed, Denied, AllowedOrDenied.</param>
        /// <param name="permissions">Only that entities appear in the output that have permission settings in connection with the given permissions.</param>
        public virtual IEnumerable<int> GetRelatedIdentities(int entityId, PermissionLevel level, IEnumerable<PermissionTypeBase> permissions)
        {
            return _permissionQuery.GetRelatedIdentities(this, entityId, level, permissions);
        }
        /// <summary>
        /// Returns all entity ids in the requested entity's direct children that have any permission setting
        /// filtered by permission value, user or group, and a permission mask
        /// </summary>
        /// <param name="entityId">Id of the entity.</param>
        /// <param name="level">Filtering by the permission value. It can be Allowed, Denied, AllowedOrDenied.</param>
        /// <param name="identityId">Id of the group or user.</param>
        /// <param name="permissions">Only those entities appear in the output that have permission settings in connection with the given permissions.</param>
        public virtual IEnumerable<int> GetRelatedEntitiesOneLevel(int entityId, PermissionLevel level, int identityId, IEnumerable<PermissionTypeBase> permissions)
        {
            return _permissionQuery.GetRelatedEntitiesOneLevel(this, entityId, level, identityId, permissions);
        }

        /// <summary>
        /// Returns Ids of all users that have all given permission on the entity.
        /// User will be resulted even if the permissions are granted on a group where she is member directly or indirectly.
        /// </summary>
        /// <param name="entityId">Id of the entity.</param>
        /// <param name="permissions">Only those users appear in the output that have permission settings in connection with the given permissions.</param>
        public virtual IEnumerable<int> GetAllowedUsers(int entityId, IEnumerable<PermissionTypeBase> permissions)
        {
            return _permissionQuery.GetAllowedUsers(this, entityId, permissions);
        }

        /// <summary>
        /// Returns Ids of all groups where the given user or group is member directly or indirectly.
        /// </summary>
        /// <param name="identityId">Id of the group or user.</param>
        /// <param name="directOnly">Switch of the direct or indirect membership.</param>
        public virtual IEnumerable<int> GetParentGroups(int identityId, bool directOnly)
        {
            return _permissionQuery.GetParentGroups(this, identityId, directOnly);
        }

        /***************** Debug info ***************/
        /// <summary>
        /// Returns an object that contains information about the execution of the last few SecurityActivities.
        /// </summary>
        public virtual SecurityActivityHistory GetRecentActivities()
        {
            return SecuritySystem.ActivityHistory.GetHistory();
        }
        /// <summary>WARNING! Do not use this method in your code. Used in consistency checker tool.</summary>
        public virtual IEnumerable<long> GetCachedMembershipForConsistencyCheck()
        {
            return SecuritySystem.Cache.GetMembershipForConsistencyCheck();
        }
        /// <summary>WARNING! Do not use this method in your code. Used in consistency checker tool.</summary>
        public virtual void GetFlatteningForConsistencyCheck(out IEnumerable<long> missingInFlattening, out IEnumerable<long> unknownInFlattening)
        {
            SecuritySystem.Cache.GetFlatteningForConsistencyCheck(out missingInFlattening, out unknownInFlattening);
        }
        /// <summary>WARNING! Do not use this method in your code. Used in consistency checker tool.</summary>
        public virtual IDictionary<int, SecurityEntity> GetCachedEntitiesForConsistencyCheck()
        {
            return SecuritySystem.Cache.Entities;
        }

    }
}
