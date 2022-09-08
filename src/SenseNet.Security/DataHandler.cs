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
    public class DataHandler
    {
        private readonly ISecurityDataProvider _dataProvider;
        private readonly MessagingOptions _messagingOptions;
        internal SecurityEntityManager EntityManager { get; set; } // Property injection

        public DataHandler(ISecurityDataProvider dataProvider, IOptions<MessagingOptions> messagingOptions)
        {
            _dataProvider = dataProvider;
            _messagingOptions = messagingOptions.Value;
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

        [Obsolete("Use async version instead.", true)]
        public IDictionary<int, SecurityEntity> LoadSecurityEntities()
        {
            return LoadSecurityEntitiesAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<IDictionary<int, SecurityEntity>> LoadSecurityEntitiesAsync(CancellationToken cancel)
        {
            if (!await IsDatabaseReadyAsync(cancel))
                return new Dictionary<int, SecurityEntity>();

            var count = await _dataProvider.GetEstimatedEntityCountAsync(cancel);
            var capacity = count + count / 10;

            var entities = new Dictionary<int, SecurityEntity>(capacity);
            var relations = new List<Tuple<SecurityEntity, int>>(capacity); // first is Id, second is ParentId

            foreach (var storedEntity in await _dataProvider.LoadSecurityEntitiesAsync(cancel))
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

        [Obsolete("Use async version instead.", true)]
        public IDictionary<int, SecurityGroup> LoadAllGroups()
        {
            return LoadAllGroupsAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<IDictionary<int, SecurityGroup>> LoadAllGroupsAsync(CancellationToken cancel)
        {
            if (!await IsDatabaseReadyAsync(CancellationToken.None))
                return new Dictionary<int, SecurityGroup>();

            var groups = await _dataProvider.LoadAllGroupsAsync(cancel);
            return groups.ToDictionary(x => x.Id);
        }

        [Obsolete("Use async version instead.", true)]
        public Dictionary<int, AclInfo> LoadAcls()
        {
            return LoadAclsAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
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

        [Obsolete("Use async version instead.", true)]
        public StoredSecurityEntity GetStoredSecurityEntity(int entityId)
        {
            return GetStoredSecurityEntityAsync(entityId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<StoredSecurityEntity> GetStoredSecurityEntityAsync(int entityId, CancellationToken cancel)
        {
            return await _dataProvider.LoadStoredSecurityEntityAsync(entityId, cancel);
        }

        public Task CreateSecurityEntityAsync(int entityId, int parentEntityId, int ownerId, CancellationToken cancel)
        {
            return CreateSecurityEntityAsync(entityId, parentEntityId, ownerId, false, cancel);
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

            await _dataProvider.InsertSecurityEntityAsync(entity, cancel);
        }

        public async Task ModifySecurityEntityOwnerAsync(int entityId, int ownerId, CancellationToken cancel)
        {
            var entity = await _dataProvider.LoadStoredSecurityEntityAsync(entityId, cancel);
            if (entity == null)
                throw new EntityNotFoundException("Cannot update a SecurityEntity beacuse it does not exist: " + entityId);
            entity.OwnerId = ownerId;
            await _dataProvider.UpdateSecurityEntityAsync(entity, cancel);
        }
        
        public Task DeleteSecurityEntityAsync(int entityId, CancellationToken cancel)
        {
            return _dataProvider.DeleteEntitiesAndEntriesAsync(entityId, cancel);
        }

        public async Task MoveSecurityEntityAsync(int sourceId, int targetId, CancellationToken cancel)
        {
            var source = await _dataProvider.LoadStoredSecurityEntityAsync(sourceId, cancel);
            if (source == null)
                throw new EntityNotFoundException("Cannot move the entity because it does not exist: " + sourceId);
            var target = await _dataProvider.LoadStoredSecurityEntityAsync(targetId, cancel);
            if (target == null)
                throw new EntityNotFoundException("Cannot move the entity because the target does not exist: " + targetId);

            // moving
            await _dataProvider.MoveSecurityEntityAsync(sourceId, targetId, cancel);
        }

        public async Task BreakInheritanceAsync(int entityId, CancellationToken cancel)
        {
            var entity = await _dataProvider.LoadStoredSecurityEntityAsync(entityId, cancel);
            if (entity == null)
                throw new EntityNotFoundException("Cannot break inheritance because the entity does not exist: " + entityId);
            entity.IsInherited = false;
            await _dataProvider.UpdateSecurityEntityAsync(entity, cancel);
        }

        public async Task UnBreakInheritanceAsync(int entityId, CancellationToken cancel)
        {
            var entity = await _dataProvider.LoadStoredSecurityEntityAsync(entityId, cancel);
            if (entity == null)
                throw new EntityNotFoundException("Cannot undo break inheritance because the entity does not exist: " + entityId);
            entity.IsInherited = true;
            await _dataProvider.UpdateSecurityEntityAsync(entity, cancel);
        }

        public Task<IEnumerable<StoredAce>> LoadPermissionEntriesAsync(IEnumerable<int> entityIds, CancellationToken cancel)
        {
            return _dataProvider.LoadPermissionEntriesAsync(entityIds, cancel);
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
                    await _dataProvider.WritePermissionEntriesAsync(aces, cancel);
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

        public Task RemovePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            return _dataProvider.RemovePermissionEntriesAsync(aces, cancel);
        }

        //==============================================================================================

        internal Messaging.CompletionState LoadCompletionState(out int lastDatabaseId)
        {
            var isDbReady = IsDatabaseReadyAsync(CancellationToken.None).GetAwaiter().GetResult();
            var ids = isDbReady 
                ? _dataProvider.GetUnprocessedActivityIdsAsync(CancellationToken.None)
                    .ConfigureAwait(false).GetAwaiter().GetResult()
                : Array.Empty<int>();
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
        //UNDONE:x: Async version (uses out params)

        internal void SaveActivity(SecurityActivity activity)
        {
            var id = _dataProvider.SaveSecurityActivity(activity, out var bodySize);
            activity.BodySize = bodySize;
            activity.Id = id;
        }

        internal Task<int> GetLastSecurityActivityIdAsync(DateTime startedTime, CancellationToken cancel)
        {
            return _dataProvider.GetLastSecurityActivityIdAsync(startedTime, cancel);
        }

        internal IEnumerable<SecurityActivity> LoadSecurityActivities(int from, int to, int count, bool executingUnprocessedActivities)
        {
            return _dataProvider.LoadSecurityActivities(from, to, count, executingUnprocessedActivities);
        }

        internal IEnumerable<SecurityActivity> LoadSecurityActivities(int[] gaps, bool executingUnprocessedActivities)
        {
            return _dataProvider.LoadSecurityActivities(gaps, executingUnprocessedActivities);
        }

        internal SecurityActivity LoadBigSecurityActivity(int id)
        {
            return _dataProvider.LoadSecurityActivity(id);
        }

        internal void CleanupSecurityActivities()
        {
            if (!IsDatabaseReadyAsync(CancellationToken.None).GetAwaiter().GetResult())
                return;

            _dataProvider.CleanupSecurityActivities(_messagingOptions.SecurityActivityLifetimeInMinutes);
        }


        internal Messaging.SecurityActivityExecutionLock AcquireSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            var timeout = Debugger.IsAttached
                ? int.MaxValue
                : Configuration.Messaging.SecurityActivityExecutionLockTimeoutInSeconds;

            return _dataProvider.AcquireSecurityActivityExecutionLock(securityActivity, timeout);
        }
        //internal void RefreshSecurityActivityExecutionLock(SecurityActivity securityActivity)
        //{
        //    _dataProvider.RefreshSecurityActivityExecutionLock(securityActivity);
        //}
        //internal void ReleaseSecurityActivityExecutionLock(SecurityActivity securityActivity, bool fullExecutionEnabled)
        //{
        //    if(fullExecutionEnabled)
        //        _dataProvider.ReleaseSecurityActivityExecutionLock(securityActivity);
        //}

        /*============================================================================================== Membership */

        [Obsolete("Use async version instead.", true)]
        public SecurityGroup GetSecurityGroup(int groupId)
        {
            return _dataProvider.LoadSecurityGroupAsync(groupId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task<SecurityGroup> GetSecurityGroupAsync(int groupId, CancellationToken cancel)
        {
            return _dataProvider.LoadSecurityGroupAsync(groupId, cancel);
        }

        internal Task DeleteUserAsync(int userId, CancellationToken cancel)
        {
            return _dataProvider.DeleteIdentityAndRelatedEntriesAsync(userId, cancel);
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
            await _dataProvider.AddMembersAsync(groupId, userMembers, groupMembers, cancel);
            if (parentGroups != null)
                foreach (var parentGroupId in parentGroups.Distinct())
                    await _dataProvider.AddMembersAsync(parentGroupId, null, new[] { groupId }, cancel);
        }

        internal async Task RemoveMembersAsync(int groupId, IEnumerable<int> userMembers,
            IEnumerable<int> groupMembers, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            await _dataProvider.RemoveMembersAsync(groupId, userMembers, groupMembers, cancel);
            if (parentGroups != null)
                foreach (var parentGroupId in parentGroups.Distinct())
                    await _dataProvider.RemoveMembersAsync(parentGroupId, null, new[] { groupId }, cancel);
        }

        internal async Task AddUserToGroupsAsync(int userId, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            foreach (var parentGroupId in parentGroups.Distinct())
                await _dataProvider.AddMembersAsync(parentGroupId, new[] { userId }, null, cancel);
        }

        internal async Task RemoveUserFromGroupsAsync(int userId, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            foreach (var parentGroupId in parentGroups.Distinct())
                await _dataProvider.RemoveMembersAsync(parentGroupId, new[] { userId }, null, cancel);
        }
    }
}
