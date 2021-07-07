using SenseNet.Security.Messaging.SecurityMessages;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace SenseNet.Security
{
    internal class DataHandler
    {
        private SecuritySystem _securitySystem;

        public DataHandler(SecuritySystem securitySystem)
        {
            _securitySystem = securitySystem;
        }

        public IDictionary<int, SecurityEntity> LoadSecurityEntities(ISecurityDataProvider dataProvider)
        {
            var count = dataProvider.GetEstimatedEntityCount();
            var capacity = count + count / 10;

            var entities = new Dictionary<int, SecurityEntity>(capacity);
            var relations = new List<Tuple<SecurityEntity, int>>(capacity); // first is Id, second is ParentId

            foreach (var storedEntity in dataProvider.LoadSecurityEntities())
            {
                var entity = new SecurityEntity
                {
                    Id = storedEntity.Id,
                    IsInherited = storedEntity.IsInherited,
                    OwnerId = storedEntity.OwnerId
                };

                entities.Add(entity.Id, entity);

                // memorize relations
                if (storedEntity.ParentId != default)
                    relations.Add(new Tuple<SecurityEntity, int>(entity, storedEntity.ParentId));
            }

            // set parent/child relationship
            foreach (var (securityEntity, parentId) in relations)
            {
                var parentEntity = entities[parentId];
                securityEntity.Parent = parentEntity;
                parentEntity.AddChild_Unsafe(securityEntity);
            }

            return new ConcurrentDictionary<int, SecurityEntity>(entities);
        }

        public IDictionary<int, SecurityGroup> LoadAllGroups(ISecurityDataProvider dataProvider)
        {
            var groups = dataProvider.LoadAllGroups();
            return groups.ToDictionary(x => x.Id);
        }
        public Dictionary<int, AclInfo> LoadAcls(ISecurityDataProvider dataProvider, IDictionary<int, SecurityEntity> entities)
        {
            var acls = new Dictionary<int, AclInfo>();

            foreach (var storedAce in dataProvider.LoadAllAces())
            {
                if (!acls.TryGetValue(storedAce.EntityId, out var acl))
                {
                    acl = new AclInfo(storedAce.EntityId);
                    acls.Add(acl.EntityId, acl);
                }
                acl.Entries.Add(new AceInfo { EntryType = storedAce.EntryType, IdentityId = storedAce.IdentityId, LocalOnly = storedAce.LocalOnly, AllowBits = storedAce.AllowBits, DenyBits = storedAce.DenyBits });
            }

            return acls;
        }

        public StoredSecurityEntity GetStoredSecurityEntity(ISecurityDataProvider dataProvider, int entityId)
        {
            return dataProvider.LoadStoredSecurityEntity(entityId);
        }

        public void CreateSecurityEntity(int entityId, int parentEntityId, int ownerId)
        {
            CreateSecurityEntity(entityId, parentEntityId, ownerId, false);
        }
        public void CreateSecurityEntitySafe(int entityId, int parentEntityId, int ownerId)
        {
            CreateSecurityEntity(entityId, parentEntityId, ownerId, true);
        }
        private void CreateSecurityEntity(int entityId, int parentEntityId, int ownerId, bool safe)
        {
            if (entityId == default)
                throw new ArgumentException("entityId cannot be default(int)");

            if (parentEntityId != default)
            {
                // load or create parent
                var parent = safe
                    ? _securitySystem.EntityManager.GetEntitySafe(parentEntityId, false)
                    : _securitySystem.EntityManager.GetEntity(parentEntityId, false);
                if (parent == null)
                    throw new EntityNotFoundException(
                        $"Cannot create entity {entityId} because its parent {parentEntityId} does not exist.");
            }

            var entity = new StoredSecurityEntity
            {
                Id = entityId,
                ParentId = parentEntityId,
                IsInherited = true,
                OwnerId = ownerId
            };

            _securitySystem.SecurityDataProvider.InsertSecurityEntity(entity);
        }

        public void ModifySecurityEntityOwner(SecurityContext context, int entityId, int ownerId)
        {
            var entity = context.DataProvider.LoadStoredSecurityEntity(entityId);
            if (entity == null)
                throw new EntityNotFoundException("Cannot update a SecurityEntity beacuse it does not exist: " + entityId);
            entity.OwnerId = ownerId;
            context.DataProvider.UpdateSecurityEntity(entity);
        }
        
        public void DeleteSecurityEntity(SecurityContext context, int entityId)
        {
            context.DataProvider.DeleteEntitiesAndEntries(entityId);
        }

        public void MoveSecurityEntity(SecurityContext context, int sourceId, int targetId)
        {
            var source = context.DataProvider.LoadStoredSecurityEntity(sourceId);
            if (source == null)
                throw new EntityNotFoundException("Cannot move the entity because it does not exist: " + sourceId);
            var target = context.DataProvider.LoadStoredSecurityEntity(targetId);
            if (target == null)
                throw new EntityNotFoundException("Cannot move the entity because the target does not exist: " + targetId);

            // moving
            context.DataProvider.MoveSecurityEntity(sourceId, targetId);
        }

        public void BreakInheritance(SecurityContext context, int entityId)
        {
            var entity = context.DataProvider.LoadStoredSecurityEntity(entityId);
            if (entity == null)
                throw new EntityNotFoundException("Cannot break inheritance because the entity does not exist: " + entityId);
            entity.IsInherited = false;
            context.DataProvider.UpdateSecurityEntity(entity);
        }

        [Obsolete("Use the overload with correct name.", true)]
        public void UnbreakInheritance(SecurityContext context, int entityId)
        {
            UnBreakInheritance(context, entityId);
        }
        public void UnBreakInheritance(SecurityContext context, int entityId)
        {
            var entity = context.DataProvider.LoadStoredSecurityEntity(entityId);
            if (entity == null)
                throw new EntityNotFoundException("Cannot undo break inheritance because the entity does not exist: " + entityId);
            entity.IsInherited = true;
            context.DataProvider.UpdateSecurityEntity(entity);
        }

        public void WritePermissionEntries(IEnumerable<StoredAce> aces)
        {
            var softReload = false;
            var hardReload = false;

            for (var i = 0; i < 3; i++)
            {
                try
                {
                    // ReSharper disable once PossibleMultipleEnumeration
                    _securitySystem.SecurityDataProvider.WritePermissionEntries(aces);
                    return;
                }
                catch (SecurityStructureException)
                {
                    // first error
                    if (!softReload)
                    {
                        // Compensate a possible missing entity: try to load them all. If one of the entities 
                        // is really missing, this will correctly throw an entity not found exception.
                        // ReSharper disable once PossibleMultipleEnumeration
                        foreach (var entityId in aces.Select(a => a.EntityId).Distinct())
                        {
                            _securitySystem.EntityManager.GetEntity(entityId, true);
                        }

                        softReload = true;
                        continue;
                    }

                    // second error
                    if (!hardReload)
                    {
                        // If the soft reload did not work, that means there is an entity that is in memory but
                        // is missing from the database. In this case we have to find that entity in the list
                        // and re-create it in the db.

                        //TODO: HARD RELOAD

                        hardReload = true;
                        continue;
                    }

                    throw;
                } 
            }
        }

        public void RemovePermissionEntries(SecurityContext context, IEnumerable<StoredAce> aces)
        {
            context.DataProvider.RemovePermissionEntries(aces);
        }

        //==============================================================================================

        internal Messaging.CompletionState LoadCompletionState(ISecurityDataProvider dataProvider, out int lastDatabaseId)
        {
            var ids = dataProvider.GetUnprocessedActivityIds();
            lastDatabaseId = ids.LastOrDefault();

            var result = new Messaging.CompletionState();

            // there is no unprocessed: last item is the last database id
            if (ids.Length <= 1)
            {
                result.LastActivityId = lastDatabaseId;
                return result;
            }

            // there is only one unprocessed element
            if (ids.Length == 2)
            {
                result.LastActivityId = lastDatabaseId;
                result.Gaps = new[] { ids[ids.Length - 2] };
                return result;
            }

            // if last unprocessed and last database id does not equal,
            // each item is gap
            if (lastDatabaseId != ids[ids.Length - 2])
            {
                //                     i-2     -1
                // _,_,3,_,_,6,_,8,9,10,11    ,12
                result.LastActivityId = lastDatabaseId;
                result.Gaps = ids.Take(ids.Length - 1).ToArray();
                return result;
            }

            //                        i-2     -1
            // _,_,3,_,_,6,_,8,9,10,11,12    ,12
            var continuousFrom = 0;
            for (var i = ids.Length - 2; i >= 1; i--)
            {
                if (ids[i] != ids[i - 1] + 1)
                {
                    continuousFrom = i;
                    break;
                }
            }

            result.LastActivityId = ids[continuousFrom] - 1;
            result.Gaps = ids.Take(continuousFrom).ToArray();

            return result;
        }

        internal void SaveActivity(SecurityActivity activity)
        {
            var id = activity.Context.DataProvider.SaveSecurityActivity(activity, out var bodySize);
            activity.BodySize = bodySize;
            activity.Id = id;
        }

        internal int GetLastSecurityActivityId(DateTime startedTime)
        {
            return _securitySystem.SecurityDataProvider.GetLastSecurityActivityId(startedTime);
        }

        internal IEnumerable<SecurityActivity> LoadSecurityActivities(int from, int to, int count, bool executingUnprocessedActivities)
        {
            return _securitySystem.SecurityDataProvider.LoadSecurityActivities(from, to, count, executingUnprocessedActivities);
        }

        internal IEnumerable<SecurityActivity> LoadSecurityActivities(int[] gaps, bool executingUnprocessedActivities)
        {
            return _securitySystem.SecurityDataProvider.LoadSecurityActivities(gaps, executingUnprocessedActivities);
        }

        internal SecurityActivity LoadBigSecurityActivity(int id)
        {
            return _securitySystem.SecurityDataProvider.LoadSecurityActivity(id);
        }

        internal void CleanupSecurityActivities()
        {
            _securitySystem.SecurityDataProvider.CleanupSecurityActivities(Configuration.Messaging.SecurityActivityLifetimeInMinutes);
        }


        internal Messaging.SecurityActivityExecutionLock AcquireSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            var timeout = Debugger.IsAttached
                ? int.MaxValue
                : Configuration.Messaging.SecurityActivityExecutionLockTimeoutInSeconds;

            return securityActivity.Context.DataProvider
                .AcquireSecurityActivityExecutionLock(securityActivity, timeout);
        }
        internal void RefreshSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            securityActivity.Context.DataProvider.RefreshSecurityActivityExecutionLock(securityActivity);
        }
        internal void ReleaseSecurityActivityExecutionLock(SecurityActivity securityActivity, bool fullExecutionEnabled)
        {
            if(fullExecutionEnabled)
                securityActivity.Context.DataProvider.ReleaseSecurityActivityExecutionLock(securityActivity);
        }

        /*============================================================================================== Membership */

        public SecurityGroup GetSecurityGroup(SecurityContext context, int groupId)
        {
            return context.DataProvider.LoadSecurityGroup(groupId);
        }

        internal void DeleteUser(SecurityContext context, int userId)
        {
            context.DataProvider.DeleteIdentityAndRelatedEntries(userId);
        }

        public void DeleteSecurityGroup(SecurityContext context, int groupId)
        {
            context.DataProvider.DeleteIdentityAndRelatedEntries(groupId);
        }

        internal void DeleteIdentities(SecurityContext context, IEnumerable<int> ids)
        {
            context.DataProvider.DeleteIdentitiesAndRelatedEntries(ids);
        }

        internal void AddMembers(SecurityContext context, int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, IEnumerable<int> parentGroups)
        {
            context.DataProvider.AddMembers(groupId, userMembers, groupMembers);
            if (parentGroups != null)
                foreach (var parentGroupId in parentGroups.Distinct())
                    context.DataProvider.AddMembers(parentGroupId, null, new[] { groupId });
        }

        internal void RemoveMembers(SecurityContext context, int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, IEnumerable<int> parentGroups)
        {
            context.DataProvider.RemoveMembers(groupId, userMembers, groupMembers);
            if (parentGroups != null)
                foreach (var parentGroupId in parentGroups.Distinct())
                    context.DataProvider.RemoveMembers(parentGroupId, null, new[] { groupId });
        }

        internal void AddUserToGroups(SecurityContext context, int userId, IEnumerable<int> parentGroups)
        {
            foreach (var parentGroupId in parentGroups.Distinct())
                context.DataProvider.AddMembers(parentGroupId, new[] { userId }, null);
        }

        internal void RemoveUserFromGroups(SecurityContext context, int userId, IEnumerable<int> parentGroups)
        {
            foreach (var parentGroupId in parentGroups.Distinct())
                context.DataProvider.RemoveMembers(parentGroupId, new[] { userId }, null);
        }
    }
}
