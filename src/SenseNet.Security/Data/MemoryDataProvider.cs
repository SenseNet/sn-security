using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SenseNet.Security.Messaging.SecurityMessages;
// ReSharper disable InconsistentlySynchronizedField

namespace SenseNet.Security.Data
{
    /// <summary>
    /// Complete ISecurityDataProvider implementation only for testing purposes.
    /// Do not use this class in any business solution.
    /// </summary>
    public class MemoryDataProvider : ISecurityDataProvider
    {
        private readonly object _messageLock = new object();
        private readonly object _acesLock = new object();

        internal DatabaseStorage Storage { get; private set; }

        private MemoryDataProvider()
        {
            Storage = DatabaseStorage.CreateEmpty();
        }

        /// <summary>
        /// Initializes a new instance of the MemoryDataProvider
        /// </summary>
        /// <param name="storage"></param>
        public MemoryDataProvider(DatabaseStorage storage)
        {
            Storage = storage;
        }

        /* ===================================================================== interface implementation */

        /// <summary>
        /// Not used in this case.
        /// </summary>
        public string ConnectionString { get; set; }

        public IActivitySerializer ActivitySerializer { get; set; }

        /// <inheritdoc />
        public void InstallDatabase()
        {
            // do nothing
        }

        public Task<bool> IsDatabaseReadyAsync(CancellationToken cancel)
        {
            return Task.FromResult(true);
        }

        public int GetEstimatedEntityCount()
        {
            return GetEstimatedEntityCountAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task<int> GetEstimatedEntityCountAsync(CancellationToken cancel)
        {
            return Task.FromResult(Storage.Entities.Count);
        }

        [Obsolete("Use async version instead.", true)]
        public IEnumerable<StoredSecurityEntity> LoadSecurityEntities()
        {
            return LoadSecurityEntitiesAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task<IEnumerable<StoredSecurityEntity>> LoadSecurityEntitiesAsync(CancellationToken cancel)
        {
            return Task.FromResult((IEnumerable<StoredSecurityEntity>)Storage.Entities.Values);
        }

        [Obsolete("Use async version instead.", true)]
        public IEnumerable<int> LoadAffectedEntityIdsByEntriesAndBreaks()
        {
            lock (_acesLock)
            {
                var byEntries = Storage.Aces.Select(a => a.EntityId);
                var byBreaks = Storage.Entities.Values.Where(e => e.IsInherited == false).Select(e => e.Id);
                var result = byEntries.Union(byBreaks).Distinct().ToArray();
                return result;
            }
        }
        public Task<IEnumerable<int>> LoadAffectedEntityIdsByEntriesAndBreaksAsync(CancellationToken cancel)
        {
            lock (_acesLock)
            {
                var byEntries = Storage.Aces.Select(a => a.EntityId);
                var byBreaks = Storage.Entities.Values.Where(e => e.IsInherited == false).Select(e => e.Id);
                var result = byEntries.Union(byBreaks).Distinct().ToArray();
                return Task.FromResult((IEnumerable<int>)result);
            }
        }

        [Obsolete("Use async version instead.", true)]
        public IEnumerable<SecurityGroup> LoadAllGroups()
        {
            return LoadAllGroupsAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task<IEnumerable<SecurityGroup>> LoadAllGroupsAsync(CancellationToken cancel)
        {
            var groups = new Dictionary<int, SecurityGroup>();
            foreach (var membership in Storage.Memberships)
            {
                var group = EnsureGroup(membership.GroupId, groups);
                if (membership.IsUser)
                {
                    group.UserMemberIds.Add(membership.MemberId);
                }
                else
                {
                    var memberGroup = EnsureGroup(membership.MemberId, groups);
                    group.Groups.Add(memberGroup);
                    memberGroup.ParentGroups.Add(group);
                }
            }
            return Task.FromResult((IEnumerable<SecurityGroup>)groups.Values);
        }

        private SecurityGroup EnsureGroup(int groupId, Dictionary<int, SecurityGroup> groups)
        {
            if (!groups.TryGetValue(groupId, out var group))
            {
                group = new SecurityGroup(groupId);
                groups.Add(group.Id, group);
            }
            return group;
        }

        /// <inheritdoc />
        public IEnumerable<StoredAce> LoadAllAces()
        {
            lock (_acesLock)
            {
                foreach (var dbItem in Storage.Aces)
                {
                    // return with a copy
                    yield return new StoredAce
                    {
                        EntityId = dbItem.EntityId,
                        EntryType = dbItem.EntryType,
                        IdentityId = dbItem.IdentityId,
                        LocalOnly = dbItem.LocalOnly,
                        AllowBits = dbItem.AllowBits,
                        DenyBits = dbItem.DenyBits
                    };
                }
            }
        }

        [Obsolete("Use async version instead.", true)]
        public StoredSecurityEntity LoadStoredSecurityEntity(int entityId)
        {
            return LoadStoredSecurityEntityAsync(entityId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task<StoredSecurityEntity> LoadStoredSecurityEntityAsync(int entityId, CancellationToken cancel)
        {
            Storage.Entities.TryGetValue(entityId, out var entity);
            return Task.FromResult(entity);
        }

        [Obsolete("Use async version instead.", true)]
        public void InsertSecurityEntity(StoredSecurityEntity entity)
        {
            InsertSecurityEntityAsync(entity, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task InsertSecurityEntityAsync(StoredSecurityEntity entity, CancellationToken cancel)
        {
            var origEntity = await LoadStoredSecurityEntityAsync(entity.Id, cancel);
            if (origEntity != null)
                return;

            Storage.Entities[entity.Id] = entity;
        }

        [Obsolete("Use async version instead.", true)]
        public void UpdateSecurityEntity(StoredSecurityEntity entity)
        {
            UpdateSecurityEntityAsync(entity, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task UpdateSecurityEntityAsync(StoredSecurityEntity entity, CancellationToken cancel)
        {
            var oldEntity = await LoadStoredSecurityEntityAsync(entity.Id, cancel);
            if (oldEntity == null)
                throw new EntityNotFoundException("Cannot update entity because it does not exist: " + entity.Id);
            Storage.Entities[entity.Id] = entity;
        }

        [Obsolete("Use async version instead.", true)]
        public void DeleteSecurityEntity(int entityId)
        {
            DeleteSecurityEntityAsync(entityId, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task DeleteSecurityEntityAsync(int entityId, CancellationToken cancel)
        {
            Storage.Entities.Remove(entityId);
            return Task.CompletedTask;
        }

        [Obsolete("Use async version instead.", true)]
        public void MoveSecurityEntity(int sourceId, int targetId)
        {
            MoveSecurityEntityAsync(sourceId, targetId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task MoveSecurityEntityAsync(int sourceId, int targetId, CancellationToken cancel)
        {
            var source = await LoadStoredSecurityEntityAsync(sourceId, cancel);
            if (source == null)
                throw new EntityNotFoundException("Cannot execute the move operation because source does not exist: " + sourceId);
            var target = await LoadStoredSecurityEntityAsync(targetId, cancel);
            if (target == null)
                throw new EntityNotFoundException("Cannot execute the move operation because target does not exist: " + targetId);
            source.ParentId = target.Id;
        }

        [Obsolete("Use async version instead.", true)]
        public SecurityGroup LoadSecurityGroup(int groupId)
        {
            return LoadSecurityGroupAsync(groupId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task<SecurityGroup> LoadSecurityGroupAsync(int groupId, CancellationToken cancel)
        {
            var group = new SecurityGroup(groupId);
            var groups = new Dictionary<int, SecurityGroup> {{group.Id, group}};
            var rows = 0;
            foreach (var membership in Storage.Memberships.Where(x => x.GroupId == groupId))
            {
                rows++;
                if (membership.IsUser)
                {
                    group.UserMemberIds.Add(membership.MemberId);
                }
                else
                {
                    var memberGroup = EnsureGroup(membership.MemberId, groups);
                    group.Groups.Add(memberGroup);
                    memberGroup.ParentGroups.Add(group);
                }
            }

            return Task.FromResult(rows == 0 ? null : group);
        }

        //public void AddOrModifySecurityGroup(int groupId, IEnumerable<int> userIds)
        //{
        //    _storage.Groups[groupId] = new SecurityGroup
        //    {
        //        Id = groupId,
        //        UserMemberIds = userIds.ToArray()
        //    };
        //}
        //public void DeleteSecurityGroup(int groupId)
        //{
        //    var group = LoadSecurityGroup(groupId);
        //    if (group != null)
        //        _storage.Groups.Remove(groupId);
        //}

        [Obsolete("Use async version instead.", true)]
        public IEnumerable<StoredAce> LoadAllPermissionEntries()
        {
            return LoadAllPermissionEntriesAsync(CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task<IEnumerable<StoredAce>> LoadAllPermissionEntriesAsync(CancellationToken cancel)
        {
            lock (_acesLock)
                return Task.FromResult((IEnumerable<StoredAce>)Storage.Aces.Select(x => x.Clone()).ToArray());
        }

        [Obsolete("Use async version instead.", true)]
        public IEnumerable<StoredAce> LoadPermissionEntries(IEnumerable<int> entityIds)
        {
            return LoadPermissionEntriesAsync(entityIds, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task<IEnumerable<StoredAce>> LoadPermissionEntriesAsync(IEnumerable<int> entityIds, CancellationToken cancel)
        {
            lock (_acesLock)
                return Task.FromResult((IEnumerable<StoredAce>)Storage.Aces.Where(a => entityIds.Contains(a.EntityId)).ToArray());
        }

        [Obsolete("Use async version instead.", true)]
        public void WritePermissionEntries(IEnumerable<StoredAce> aces)
        {
            WritePermissionEntriesAsync(aces, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task WritePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            lock (_acesLock)
            {
                foreach (var ace in aces)
                {
                    var old = Storage.Aces.FirstOrDefault(x => x.EntityId == ace.EntityId && x.EntryType == ace.EntryType && x.IdentityId == ace.IdentityId && x.LocalOnly == ace.LocalOnly);
                    if (old != null)
                        Storage.Aces.Remove(old);
                    Storage.Aces.Add(ace);
                }
            }
            return Task.CompletedTask;
        }

        [Obsolete("Use async version instead.", true)]
        public void RemovePermissionEntries(IEnumerable<StoredAce> aces)
        {
            RemovePermissionEntriesAsync(aces, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task RemovePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            lock (_acesLock)
            {
                foreach (var ace in aces)
                {
                    var old = Storage.Aces.FirstOrDefault(x => x.EntityId == ace.EntityId && x.EntryType == ace.EntryType && x.IdentityId == ace.IdentityId && x.LocalOnly == ace.LocalOnly);
                    if (old != null)
                        Storage.Aces.Remove(old);
                }
            }
            return Task.CompletedTask;
        }

        [Obsolete("Use async version instead.", true)]
        public void RemovePermissionEntriesByEntity(int entityId)
        {
            RemovePermissionEntriesByEntityAsync(entityId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task RemovePermissionEntriesByEntityAsync(int entityId, CancellationToken cancel)
        {
            lock (_acesLock)
                Storage.Aces.RemoveAll(y => y.EntityId == entityId);
            return Task.CompletedTask;
        }

        internal void RemovePermissionEntriesByGroup(int groupId)
        {
            lock (_acesLock)
                Storage.Aces.RemoveAll(x => x.IdentityId == groupId);
        }

        [Obsolete("Use async version instead.", true)]
        public void DeleteEntitiesAndEntries(int entityId)
        {
            DeleteEntitiesAndEntriesAsync(entityId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task DeleteEntitiesAndEntriesAsync(int entityId, CancellationToken cancel)
        {
            lock (_acesLock)
                Storage.Aces.RemoveAll(y => y.EntityId == entityId);

            var childIds = Storage.Entities.Values.Where(se => se.ParentId == entityId).Select(sec => sec.Id).ToArray();

            // delete children recursively
            foreach (var childEntityId in childIds)
            {
                await DeleteEntitiesAndEntriesAsync(childEntityId, cancel);
            }

            // remove the entity itself
            Storage.Entities.Remove(entityId);
        }

        public void QueryGroupRelatedEntities(int groupId, out IEnumerable<int> entityIds, out IEnumerable<int> exclusiveEntityIds)
        {
            lock (_acesLock)
            {
                var result = new List<int>();
                entityIds = Storage.Aces.Where(x => x.IdentityId == groupId).Select(x => x.EntityId).Distinct();
                // ReSharper disable once LoopCanBeConvertedToQuery
                foreach (var relatedEntityId in entityIds)
                {
                    var aces = Storage.Aces.Where(x => x.EntityId == relatedEntityId).ToArray();
                    var groupRelatedCount = aces.Count(x => x.IdentityId == groupId);
                    if (aces.Length == groupRelatedCount)
                        result.Add(relatedEntityId);
                }
                exclusiveEntityIds = result;
            }
        }

        internal int LastActivityId;

        /// <inheritdoc />
        public int SaveSecurityActivity(SecurityActivity activity, out int bodySize)
        {
            lock (_messageLock)
            {
                var id = Interlocked.Increment(ref LastActivityId);
                var body = ActivitySerializer.SerializeActivity(activity);
                bodySize = body.Length;
                Storage.Messages.Add(new Tuple<int, DateTime, byte[]>(id, DateTime.UtcNow, body));
                return id;
            }
        }

        /// <inheritdoc />
        public virtual int GetLastSecurityActivityId(DateTime startedTime)
        {
            return GetLastSecurityActivityIdAsync(startedTime, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public virtual Task<int> GetLastSecurityActivityIdAsync(DateTime startedTime, CancellationToken cancel)
        {
            lock (_messageLock)
            {
                var lastMessage = Storage.Messages?.OrderByDescending(m => m.Item1).FirstOrDefault();
                return Task.FromResult(lastMessage?.Item1 ?? 0);
            }
        }

        /// <inheritdoc />
        public int[] GetUnprocessedActivityIds()
        {
            return new[] { 0 };
        }

        /// <inheritdoc />
        public SecurityActivity[] LoadSecurityActivities(int from, int to, int count, bool executingUnprocessedActivities)
        {
            lock (_messageLock)
            {
                var result = new List<SecurityActivity>();

                foreach (var (id, _, body) in Storage.Messages.Where(x => x.Item1 >= from && x.Item1 <= to).Take(count))
                {
                    var activity = ActivitySerializer.DeserializeActivity(body);
                    if (activity == null)
                        continue;
                    activity.Id = id;
                    activity.FromDatabase = true;
                    activity.IsUnprocessedActivity = executingUnprocessedActivities;
                    result.Add(activity);
                }

                return result.ToArray();
            }
        }

        /// <inheritdoc />
        public SecurityActivity[] LoadSecurityActivities(int[] gaps, bool executingUnprocessedActivities)
        {
            lock (_messageLock)
            {
                var result = new List<SecurityActivity>();

                foreach (var (id, _, body) in Storage.Messages.Where(x => gaps.Contains(x.Item1)))
                {
                    var activity = ActivitySerializer.DeserializeActivity(body);
                    if (activity == null)
                        continue;
                    activity.Id = id;
                    activity.FromDatabase = true;
                    activity.IsUnprocessedActivity = executingUnprocessedActivities;
                    result.Add(activity);
                }

                return result.ToArray();
            }
        }

        /// <inheritdoc />
        public virtual SecurityActivity LoadSecurityActivity(int id)
        {
            lock (_messageLock)
            {
                var item = Storage.Messages.FirstOrDefault(x => x.Item1 == id);
                if (item == null)
                    return null;

                var activity = ActivitySerializer.DeserializeActivity(item.Item3);
                activity.Id = item.Item1;
                return activity;
            }
        }

        /// <inheritdoc />
        public virtual void CleanupSecurityActivities(int timeLimitInMinutes)
        {
            lock (_messageLock)
            {
                var timeLimit = DateTime.UtcNow.AddMinutes(-timeLimitInMinutes);

                foreach (var item in Storage.Messages.Where(x => x.Item2 < timeLimit).ToArray())
                    Storage.Messages.Remove(item);
            }
        }


        /// <inheritdoc />
        public Messaging.SecurityActivityExecutionLock AcquireSecurityActivityExecutionLock(SecurityActivity securityActivity, int timeoutInSeconds)
        {
            return new Messaging.SecurityActivityExecutionLock(securityActivity, this, true);
        }
        /// <inheritdoc />
        public void RefreshSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            // do nothing
        }
        /// <inheritdoc />
        public void ReleaseSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            // do nothing
        }


        //TODO: thread safety
        /// <inheritdoc />
        [Obsolete("Use async version instead.", true)]
        public void DeleteIdentityAndRelatedEntries(int identityId)
        {
            DeleteIdentityAndRelatedEntriesAsync(identityId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        //TODO: thread safety
        public Task DeleteIdentityAndRelatedEntriesAsync(int identityId, CancellationToken cancel)
        {
            Storage.Memberships.RemoveAll(m => m.GroupId == identityId || m.MemberId == identityId);
            RemovePermissionEntriesByGroup(identityId);
            return Task.CompletedTask;
        }

        [Obsolete("Use async version instead.", true)]
        public void DeleteIdentitiesAndRelatedEntries(IEnumerable<int> ids)
        {
            DeleteIdentitiesAndRelatedEntriesAsync(ids, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task DeleteIdentitiesAndRelatedEntriesAsync(IEnumerable<int> ids, CancellationToken cancel)
        {
            foreach (var id in ids)
                await DeleteIdentityAndRelatedEntriesAsync(id, cancel);
        }

        [Obsolete("Use async version instead.", true)]
        public void AddMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            AddMembersAsync(groupId, userMembers, groupMembers, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task AddMembersAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, CancellationToken cancel)
        {
            if (groupMembers != null)
            {
                foreach (var memberId in groupMembers)
                {
                    Storage.Memberships.RemoveAll(m => m.GroupId == groupId && m.MemberId == memberId);
                    Storage.Memberships.Add(new Membership { GroupId = groupId, MemberId = memberId, IsUser = false });
                }
            }
            if (userMembers != null)
            {
                foreach (var memberId in userMembers)
                {
                    Storage.Memberships.RemoveAll(m => m.GroupId == groupId && m.MemberId == memberId);
                    Storage.Memberships.Add(new Membership { GroupId = groupId, MemberId = memberId, IsUser = true });
                }
            }
            return Task.CompletedTask;;
        }

        public void RemoveMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            RemoveMembersAsync(groupId, userMembers, groupMembers, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task RemoveMembersAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, CancellationToken cancel)
        {
            if (groupMembers != null)
                foreach (var memberId in groupMembers)
                    Storage.Memberships.RemoveAll(m => m.GroupId == groupId && m.MemberId == memberId);
            if (userMembers != null)
                foreach (var memberId in userMembers)
                    Storage.Memberships.RemoveAll(m => m.GroupId == groupId && m.MemberId == memberId);
            return Task.CompletedTask;
        }

        //============================================================

        /// <inheritdoc />
        public IEnumerable<long> GetMembershipForConsistencyCheck()
        {
            return Storage.Memberships.Select(m => (Convert.ToInt64(m.GroupId) << 32) + m.MemberId).ToArray();
        }
    }
}
