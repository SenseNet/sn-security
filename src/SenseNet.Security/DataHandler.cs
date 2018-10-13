using SenseNet.Security.Messaging.SecurityMessages;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace SenseNet.Security
{
    internal static class DataHandler
    {
        public static IDictionary<int, SecurityEntity> LoadSecurityEntities(ISecurityDataProvider dataProvider)
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
                if (storedEntity.ParentId != default(int))
                    relations.Add(new Tuple<SecurityEntity, int>(entity, storedEntity.ParentId));
            }

            // set parent/child relationship
            foreach (var rel in relations)
            {
                var parentEntity = entities[rel.Item2];
                rel.Item1.Parent = parentEntity;
                parentEntity.AddChild_Unsafe(rel.Item1);
            }

            return new ConcurrentDictionary<int, SecurityEntity>(entities);
        }

        public static IDictionary<int, SecurityGroup> LoadAllGroups(ISecurityDataProvider dataProvider)
        {
            var groups = dataProvider.LoadAllGroups();
            return groups.ToDictionary(x => x.Id);
        }
        public static Dictionary<int, AclInfo> LoadAcls(ISecurityDataProvider dataProvider, IDictionary<int, SecurityEntity> entities)
        {
            var acls = new Dictionary<int, AclInfo>();

            foreach (var storedAce in dataProvider.LoadAllAces())
            {
                AclInfo acl;
                if (!acls.TryGetValue(storedAce.EntityId, out acl))
                {
                    acl = new AclInfo(storedAce.EntityId);
                    acls.Add(acl.EntityId, acl);
                }
                acl.Entries.Add(new AceInfo { EntryType = storedAce.EntryType, IdentityId = storedAce.IdentityId, LocalOnly = storedAce.LocalOnly, AllowBits = storedAce.AllowBits, DenyBits = storedAce.DenyBits });
            }

            return acls;
        }

        public static StoredSecurityEntity GetStoredSecurityEntity(ISecurityDataProvider dataProvider, int entityId)
        {
            return dataProvider.LoadStoredSecurityEntity(entityId);
        }

        public static void CreateSecurityEntity(SecurityContext context, int entityId, int parentEntityId, int ownerId)
        {
            CreateSecurityEntity(context, entityId, parentEntityId, ownerId, false);
        }
        public static void CreateSecurityEntitySafe(SecurityContext context, int entityId, int parentEntityId, int ownerId)
        {
            CreateSecurityEntity(context, entityId, parentEntityId, ownerId, true);
        }
        private static void CreateSecurityEntity(SecurityContext context, int entityId, int parentEntityId, int ownerId, bool safe)
        {
            if (entityId == default(int))
                throw new ArgumentException("entityId cannot be default(int)");

            if (parentEntityId != default(int))
            {
                // load or create parent
                var parent = safe
                    ? SecurityEntity.GetEntitySafe(context, parentEntityId, false)
                    : SecurityEntity.GetEntity(context, parentEntityId, false);
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
            context.DataProvider.InsertSecurityEntity(entity);
        }

        public static void ModifySecurityEntityOwner(SecurityContext context, int entityId, int ownerId)
        {
            var entity = context.DataProvider.LoadStoredSecurityEntity(entityId);
            if (entity == null)
                throw new EntityNotFoundException("Cannot update a SecurityEntity beacuse it does not exist: " + entityId);
            entity.OwnerId = ownerId;
            context.DataProvider.UpdateSecurityEntity(entity);
        }
        
        public static void DeleteSecurityEntity(SecurityContext context, int entityId)
        {
            context.DataProvider.DeleteEntitiesAndEntries(entityId);
        }

        public static void MoveSecurityEntity(SecurityContext context, int sourceId, int targetId)
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

        public static void BreakInheritance(SecurityContext context, int entityId)
        {
            var entity = context.DataProvider.LoadStoredSecurityEntity(entityId);
            if (entity == null)
                throw new EntityNotFoundException("Cannot break inheritance because the entity does not exist: " + entityId);
            entity.IsInherited = false;
            context.DataProvider.UpdateSecurityEntity(entity);
        }

        public static void UnbreakInheritance(SecurityContext context, int entityId)
        {
            var entity = context.DataProvider.LoadStoredSecurityEntity(entityId);
            if (entity == null)
                throw new EntityNotFoundException("Cannot unbreak inheritance because the entity does not exist: " + entityId);
            entity.IsInherited = true;
            context.DataProvider.UpdateSecurityEntity(entity);
        }

        public static void WritePermissionEntries(SecurityContext context, IEnumerable<StoredAce> aces)
        {
            var softReload = false;
            var hardReload = false;

            for (var i = 0; i < 3; i++)
            {
                try
                {
                    // ReSharper disable once PossibleMultipleEnumeration
                    context.DataProvider.WritePermissionEntries(aces);
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
                            SecurityEntity.GetEntity(context, entityId, true);
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

        public static void RemovePermissionEntries(SecurityContext context, IEnumerable<StoredAce> aces)
        {
            context.DataProvider.RemovePermissionEntries(aces);
        }

        //==============================================================================================

        internal static Messaging.CompletionState LoadCompletionState(ISecurityDataProvider dataProvider, out int lastDatabaseId)
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

        internal static void SaveActivity(SecurityActivity activity)
        {
            int bodySize;
            var id = activity.Context.DataProvider.SaveSecurityActivity(activity, out bodySize);
            activity.BodySize = bodySize;
            activity.Id = id;
        }

        internal static int GetLastSecurityActivityId(DateTime startedTime)
        {
            return SecurityContext.General.DataProvider.GetLastSecurityActivityId(startedTime);
        }

        internal static IEnumerable<SecurityActivity> LoadSecurityActivities(int from, int to, int count, bool executingUnprocessedActivities)
        {
            return SecurityContext.General.DataProvider.LoadSecurityActivities(from, to, count, executingUnprocessedActivities);
        }

        internal static IEnumerable<SecurityActivity> LoadSecurityActivities(int[] gaps, bool executingUnprocessedActivities)
        {
            return SecurityContext.General.DataProvider.LoadSecurityActivities(gaps, executingUnprocessedActivities);
        }

        internal static SecurityActivity LoadBigSecurityActivity(int id)
        {
            return SecurityContext.General.DataProvider.LoadSecurityActivity(id);
        }

        internal static void CleanupSecurityActivities()
        {
            SecurityContext.General.DataProvider.CleanupSecurityActivities(Configuration.Messaging.SecuritActivityLifetimeInMinutes);
        }


        internal static Messaging.SecurityActivityExecutionLock AcquireSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            var timeout = Debugger.IsAttached
                ? int.MaxValue
                : Configuration.Messaging.SecurityActivityExecutionLockTimeoutInSeconds;

            return securityActivity.Context.DataProvider
                .AcquireSecurityActivityExecutionLock(securityActivity, timeout);
        }
        internal static void RefreshSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            securityActivity.Context.DataProvider.RefreshSecurityActivityExecutionLock(securityActivity);
        }
        internal static void ReleaseSecurityActivityExecutionLock(SecurityActivity securityActivity, bool fullExecutionEnabled)
        {
            if(fullExecutionEnabled)
                securityActivity.Context.DataProvider.ReleaseSecurityActivityExecutionLock(securityActivity);
        }

        /*============================================================================================== Membership */

        public static SecurityGroup GetSecurityGroup(SecurityContext context, int groupId)
        {
            return context.DataProvider.LoadSecurityGroup(groupId);
        }

        internal static void DeleteUser(SecurityContext context, int userId)
        {
            context.DataProvider.DeleteIdentityAndRelatedEntries(userId);
        }

        public static void DeleteSecurityGroup(SecurityContext context, int groupId)
        {
            context.DataProvider.DeleteIdentityAndRelatedEntries(groupId);
        }

        internal static void DeleteIdentities(SecurityContext context, IEnumerable<int> ids)
        {
            context.DataProvider.DeleteIdentitiesAndRelatedEntries(ids);
        }

        internal static void AddMembers(SecurityContext context, int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, IEnumerable<int> parentGroups)
        {
            context.DataProvider.AddMembers(groupId, userMembers, groupMembers);
            if (parentGroups != null)
                foreach (var parentGroupId in parentGroups.Distinct())
                    context.DataProvider.AddMembers(parentGroupId, null, new[] { groupId });
        }

        internal static void RemoveMembers(SecurityContext context, int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, IEnumerable<int> parentGroups)
        {
            context.DataProvider.RemoveMembers(groupId, userMembers, groupMembers);
            if (parentGroups != null)
                foreach (var parentGroupId in parentGroups.Distinct())
                    context.DataProvider.RemoveMembers(parentGroupId, null, new[] { groupId });
        }

        internal static void AddUserToGroups(SecurityContext context, int userId, IEnumerable<int> parentGroups)
        {
            foreach (var parentGroupId in parentGroups.Distinct())
                context.DataProvider.AddMembers(parentGroupId, new[] { userId }, null);
        }

        internal static void RemoveUserFromGroups(SecurityContext context, int userId, IEnumerable<int> parentGroups)
        {
            foreach (var parentGroupId in parentGroups.Distinct())
                context.DataProvider.RemoveMembers(parentGroupId, new[] { userId }, null);
        }
    }
}
