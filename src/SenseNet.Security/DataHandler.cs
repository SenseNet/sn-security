using SenseNet.Security.Messaging.SecurityMessages;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Extensions.Options;
using SenseNet.Security.Configuration;
using System.Threading.Tasks;
using System.Threading;

namespace SenseNet.Security
{
    /// <summary>
    /// Contains information about the executed activities and last activity id in the database.
    /// </summary>
    public class LoadCompletionStateResult
    {
        /// <summary>
        /// Gets or sets the current CompletionState containing information about the executed activities.
        /// </summary>
        public Messaging.CompletionState CompletionState { get; set; }
        /// <summary>
        /// Gets or sets the last executed activity id in the database.
        /// </summary>
        public int LastDatabaseId { get; set; }
    }

    public class DataHandler
    {
        private readonly ISecurityDataProvider _dataProvider;
        private readonly MessagingOptions _messagingOptions;
        internal SecurityEntityManager EntityManager { get; set; } // Property injection

        public DataHandler(ISecurityDataProvider dataProvider, IOptions<MessagingOptions> messagingOptions)
        {
            _dataProvider = dataProvider;
            _messagingOptions = messagingOptions?.Value ?? new MessagingOptions();
        }

        private bool _isDatabaseReady;
        public async Task<bool> IsDatabaseReadyAsync(CancellationToken cancel)
        {
            if (_isDatabaseReady)
                return true;

            var isReady = await _dataProvider.IsDatabaseReadyAsync(cancel).ConfigureAwait(false);

            // memorize only the positive value
            if (isReady)
                _isDatabaseReady = true;

            return isReady;
        }

        [Obsolete("Use async version instead.")]
        public IDictionary<int, SecurityEntity> LoadSecurityEntities()
        {
            return LoadSecurityEntitiesAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<IDictionary<int, SecurityEntity>> LoadSecurityEntitiesAsync(CancellationToken cancel)
        {
            if (!await IsDatabaseReadyAsync(cancel))
                return new Dictionary<int, SecurityEntity>();

            var count = await _dataProvider.GetEstimatedEntityCountAsync(cancel).ConfigureAwait(false);
            var capacity = count + count / 10;

            var entities = new Dictionary<int, SecurityEntity>(capacity);
            var relations = new List<Tuple<SecurityEntity, int>>(capacity); // first is Id, second is ParentId

            foreach (var storedEntity in await _dataProvider.LoadSecurityEntitiesAsync(cancel).ConfigureAwait(false))
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

        [Obsolete("Use async version instead.")]
        public IDictionary<int, SecurityGroup> LoadAllGroups()
        {
            return LoadAllGroupsAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<IDictionary<int, SecurityGroup>> LoadAllGroupsAsync(CancellationToken cancel)
        {
            if (!await IsDatabaseReadyAsync(CancellationToken.None))
                return new Dictionary<int, SecurityGroup>();

            var groups = await _dataProvider.LoadAllGroupsAsync(cancel).ConfigureAwait(false);
            return groups.ToDictionary(x => x.Id);
        }

        [Obsolete("Use async version instead.")]
        public Dictionary<int, AclInfo> LoadAcls()
        {
            return LoadAclsAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<Dictionary<int, AclInfo>> LoadAclsAsync(CancellationToken cancel)
        {
            if (!await IsDatabaseReadyAsync(CancellationToken.None))
                return new Dictionary<int, AclInfo>();

            var acls = new Dictionary<int, AclInfo>();

            foreach (var storedAce in _dataProvider.LoadAllAces())
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

        [Obsolete("Use async version instead.")]
        public StoredSecurityEntity GetStoredSecurityEntity(int entityId)
        {
            return GetStoredSecurityEntityAsync(entityId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<StoredSecurityEntity> GetStoredSecurityEntityAsync(int entityId, CancellationToken cancel)
        {
            return await _dataProvider.LoadStoredSecurityEntityAsync(entityId, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public void CreateSecurityEntity(int entityId, int parentEntityId, int ownerId)
        {
            CreateSecurityEntityAsync(entityId, parentEntityId, ownerId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public Task CreateSecurityEntityAsync(int entityId, int parentEntityId, int ownerId, CancellationToken cancel)
        {
            return CreateSecurityEntityAsync(entityId, parentEntityId, ownerId, false, cancel);
        }

        [Obsolete("Use async version instead.")]
        public void CreateSecurityEntitySafe(int entityId, int parentEntityId, int ownerId)
        {
            CreateSecurityEntitySafeAsync(entityId, parentEntityId, ownerId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public Task CreateSecurityEntitySafeAsync(int entityId, int parentEntityId, int ownerId, CancellationToken cancel)
        {
            return CreateSecurityEntityAsync(entityId, parentEntityId, ownerId, true, cancel);
        }
        private async Task CreateSecurityEntityAsync(int entityId, int parentEntityId, int ownerId, bool safe, CancellationToken cancel)
        {
            if (entityId == default)
                throw new ArgumentException("entityId cannot be default(int)");

            if (parentEntityId != default)
            {
                // load or create parent
                var parent = safe
                    ? EntityManager.GetEntitySafe(parentEntityId, false)
                    : EntityManager.GetEntity(parentEntityId, false);
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

            await _dataProvider.InsertSecurityEntityAsync(entity, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public void ModifySecurityEntityOwner(int entityId, int ownerId)
        {
            ModifySecurityEntityOwnerAsync(entityId, ownerId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task ModifySecurityEntityOwnerAsync(int entityId, int ownerId, CancellationToken cancel)
        {
            var entity = await _dataProvider.LoadStoredSecurityEntityAsync(entityId, cancel).ConfigureAwait(false);
            if (entity == null)
                throw new EntityNotFoundException("Cannot update a SecurityEntity beacuse it does not exist: " + entityId);
            entity.OwnerId = ownerId;
            await _dataProvider.UpdateSecurityEntityAsync(entity, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public void DeleteSecurityEntity(int entityId)
        {
            DeleteSecurityEntityAsync(entityId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public Task DeleteSecurityEntityAsync(int entityId, CancellationToken cancel)
        {
            return _dataProvider.DeleteEntitiesAndEntriesAsync(entityId, cancel);
        }

        [Obsolete("Use async version instead.")]
        public void MoveSecurityEntity(int sourceId, int targetId)
        {
            MoveSecurityEntityAsync(sourceId, targetId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task MoveSecurityEntityAsync(int sourceId, int targetId, CancellationToken cancel)
        {
            var source = await _dataProvider.LoadStoredSecurityEntityAsync(sourceId, cancel).ConfigureAwait(false);
            if (source == null)
                throw new EntityNotFoundException("Cannot move the entity because it does not exist: " + sourceId);
            var target = await _dataProvider.LoadStoredSecurityEntityAsync(targetId, cancel).ConfigureAwait(false);
            if (target == null)
                throw new EntityNotFoundException("Cannot move the entity because the target does not exist: " + targetId);

            // moving
            await _dataProvider.MoveSecurityEntityAsync(sourceId, targetId, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public void BreakInheritance(int entityId)
        {
            BreakInheritanceAsync(entityId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task BreakInheritanceAsync(int entityId, CancellationToken cancel)
        {
            var entity = await _dataProvider.LoadStoredSecurityEntityAsync(entityId, cancel).ConfigureAwait(false);
            if (entity == null)
                throw new EntityNotFoundException("Cannot break inheritance because the entity does not exist: " + entityId);
            entity.IsInherited = false;
            await _dataProvider.UpdateSecurityEntityAsync(entity, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public void UnBreakInheritance(int entityId)
        {
            UnBreakInheritanceAsync(entityId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task UnBreakInheritanceAsync(int entityId, CancellationToken cancel)
        {
            var entity = await _dataProvider.LoadStoredSecurityEntityAsync(entityId, cancel).ConfigureAwait(false);
            if (entity == null)
                throw new EntityNotFoundException("Cannot undo break inheritance because the entity does not exist: " + entityId);
            entity.IsInherited = true;
            await _dataProvider.UpdateSecurityEntityAsync(entity, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public IEnumerable<StoredAce> LoadPermissionEntries(IEnumerable<int> entityIds)
        {
            return LoadPermissionEntriesAsync(entityIds, CancellationToken.None).GetAwaiter().GetResult();
        }
        public Task<IEnumerable<StoredAce>> LoadPermissionEntriesAsync(IEnumerable<int> entityIds, CancellationToken cancel)
        {
            return _dataProvider.LoadPermissionEntriesAsync(entityIds, cancel);
        }

        [Obsolete("Use async version instead.")]
        public void WritePermissionEntries(IEnumerable<StoredAce> aces)
        {
            WritePermissionEntriesAsync(aces, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task WritePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            var softReload = false;
            var hardReload = false;

            for (var i = 0; i < 3; i++)
            {
                try
                {
                    // ReSharper disable once PossibleMultipleEnumeration
                    await _dataProvider.WritePermissionEntriesAsync(aces, cancel).ConfigureAwait(false);
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
                            EntityManager.GetEntity(entityId, true);
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

        [Obsolete("Use async version instead.")]
        public void RemovePermissionEntries(IEnumerable<StoredAce> aces)
        {
            RemovePermissionEntriesAsync(aces, CancellationToken.None).GetAwaiter().GetResult();
        }
        public Task RemovePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            return _dataProvider.RemovePermissionEntriesAsync(aces, cancel);
        }

        //==============================================================================================

        internal async Task<LoadCompletionStateResult> LoadCompletionStateAsync(CancellationToken cancel)
        {
            var isDbReady = await IsDatabaseReadyAsync(CancellationToken.None).ConfigureAwait(false);
            var ids = isDbReady 
                ? await _dataProvider.GetUnprocessedActivityIdsAsync(CancellationToken.None).ConfigureAwait(false)
                : Array.Empty<int>();
            var lastDatabaseId = ids.LastOrDefault();

            var completionState = new Messaging.CompletionState();

            // there is no unprocessed: last item is the last database id
            if (ids.Length <= 1)
            {
                completionState.LastActivityId = lastDatabaseId;
                return new LoadCompletionStateResult{CompletionState = completionState, LastDatabaseId = lastDatabaseId};
            }

            // there is only one unprocessed element
            if (ids.Length == 2)
            {
                completionState.LastActivityId = lastDatabaseId;
                completionState.Gaps = new[] { ids[ids.Length - 2] };
                return new LoadCompletionStateResult { CompletionState = completionState, LastDatabaseId = lastDatabaseId };
            }

            // if last unprocessed and last database id does not equal,
            // each item is gap
            if (lastDatabaseId != ids[ids.Length - 2])
            {
                //                     i-2     -1
                // _,_,3,_,_,6,_,8,9,10,11    ,12
                completionState.LastActivityId = lastDatabaseId;
                completionState.Gaps = ids.Take(ids.Length - 1).ToArray();
                return new LoadCompletionStateResult { CompletionState = completionState, LastDatabaseId = lastDatabaseId };
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

            completionState.LastActivityId = ids[continuousFrom] - 1;
            completionState.Gaps = ids.Take(continuousFrom).ToArray();

            return new LoadCompletionStateResult { CompletionState = completionState, LastDatabaseId = lastDatabaseId };
        }

        internal async Task SaveActivityAsync(SecurityActivity activity, CancellationToken cancel)
        {
            var result = await _dataProvider.SaveSecurityActivityAsync(activity, cancel).ConfigureAwait(false);
            activity.BodySize = result.BodySize;
            activity.Id = result.ActivityId;
        }

        internal Task<int> GetLastSecurityActivityIdAsync(DateTime startedTime, CancellationToken cancel)
        {
            return _dataProvider.GetLastSecurityActivityIdAsync(startedTime, cancel);
        }

        internal async Task<IEnumerable<SecurityActivity>> LoadSecurityActivitiesAsync(int from, int to, int count,
            bool executingUnprocessedActivities, CancellationToken cancel)
        {
            var result = await _dataProvider.LoadSecurityActivitiesAsync(from, to, count, executingUnprocessedActivities, cancel).ConfigureAwait(false);
            return result;
        }

        internal async Task<IEnumerable<SecurityActivity>> LoadSecurityActivitiesAsync(int[] gaps, bool executingUnprocessedActivities,
            CancellationToken cancel)
        {
            var result = await _dataProvider.LoadSecurityActivitiesAsync(gaps, executingUnprocessedActivities, cancel).ConfigureAwait(false);
            return result;
        }

        internal Task<SecurityActivity> LoadBigSecurityActivityAsync(int id, CancellationToken cancel)
        {
            return _dataProvider.LoadSecurityActivityAsync(id, cancel);
        }

        internal async Task CleanupSecurityActivitiesAsync(CancellationToken cancel)
        {
            if (!await IsDatabaseReadyAsync(cancel))
                return;
            await _dataProvider.CleanupSecurityActivitiesAsync(_messagingOptions.SecurityActivityLifetimeInMinutes, cancel).ConfigureAwait(false);
        }


        internal async Task<Messaging.SecurityActivityExecutionLock> AcquireSecurityActivityExecutionLockAsync(SecurityActivity securityActivity,
            CancellationToken cancel)
        {
            var timeout = Debugger.IsAttached
                ? int.MaxValue
                : Configuration.Messaging.SecurityActivityExecutionLockTimeoutInSeconds;

            return await _dataProvider.AcquireSecurityActivityExecutionLockAsync(securityActivity, timeout, cancel).ConfigureAwait(false);
        }

        /*============================================================================================== Membership */

        [Obsolete("Use async version instead.")]
        public SecurityGroup GetSecurityGroup(int groupId)
        {
            return _dataProvider.LoadSecurityGroupAsync(groupId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public Task<SecurityGroup> GetSecurityGroupAsync(int groupId, CancellationToken cancel)
        {
            return _dataProvider.LoadSecurityGroupAsync(groupId, cancel);
        }

        internal Task DeleteUserAsync(int userId, CancellationToken cancel)
        {
            return _dataProvider.DeleteIdentityAndRelatedEntriesAsync(userId, cancel);
        }

        [Obsolete("Use async version instead.")]
        public void DeleteSecurityGroup(int groupId)
        {
            DeleteSecurityGroupAsync(groupId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public Task DeleteSecurityGroupAsync(int groupId, CancellationToken cancel)
        {
            return _dataProvider.DeleteIdentityAndRelatedEntriesAsync(groupId, cancel);
        }

        internal Task DeleteIdentitiesAsync(IEnumerable<int> ids, CancellationToken cancel)
        {
            return _dataProvider.DeleteIdentitiesAndRelatedEntriesAsync(ids, cancel);
        }

        internal async Task AddMembersAsync(int groupId, IEnumerable<int> userMembers,
            IEnumerable<int> groupMembers, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            await _dataProvider.AddMembersAsync(groupId, userMembers, groupMembers, cancel).ConfigureAwait(false);
            if (parentGroups != null)
                foreach (var parentGroupId in parentGroups.Distinct())
                    await _dataProvider.AddMembersAsync(parentGroupId, null, new[] { groupId }, cancel).ConfigureAwait(false);
        }

        internal async Task RemoveMembersAsync(int groupId, IEnumerable<int> userMembers,
            IEnumerable<int> groupMembers, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            await _dataProvider.RemoveMembersAsync(groupId, userMembers, groupMembers, cancel).ConfigureAwait(false);
            if (parentGroups != null)
                foreach (var parentGroupId in parentGroups.Distinct())
                    await _dataProvider.RemoveMembersAsync(parentGroupId, null, new[] { groupId }, cancel).ConfigureAwait(false);
        }

        internal async Task AddUserToGroupsAsync(int userId, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            foreach (var parentGroupId in parentGroups.Distinct())
                await _dataProvider.AddMembersAsync(parentGroupId, new[] { userId }, null, cancel).ConfigureAwait(false);
        }

        internal async Task RemoveUserFromGroupsAsync(int userId, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            foreach (var parentGroupId in parentGroups.Distinct())
                await _dataProvider.RemoveMembersAsync(parentGroupId, new[] { userId }, null, cancel).ConfigureAwait(false);
        }
    }
}
