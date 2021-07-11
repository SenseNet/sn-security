using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using SenseNet.Security.Messaging.SecurityMessages;
// ReSharper disable InconsistentlySynchronizedField

namespace SenseNet.Security.Data
{
    /// <summary>
    /// Complete ISecurityDataProvider implementation only for testing purposes.
    /// Do not use this class in any business solution.
    /// </summary>
    public class MemoryDataProvider : ISecurityDataProvider //UNDONE: Has static members
    {
        private static readonly object MessageLock = new object();
        private static readonly object AcesLock = new object();

        internal DatabaseStorage Storage { get; private set; }

        private MemoryDataProvider()
        {
            Storage = DatabaseStorage.CreateEmpty();
        }

        /// <inheritdoc />
        public MemoryDataProvider(DatabaseStorage storage)
        {
            Storage = storage;
        }

        /* ===================================================================== interface implementation */

        //it is not used
        /// <inheritdoc />
        public string ConnectionString { get; set; }

        /// <inheritdoc />
        public void DeleteEverything()
        {
            Storage = DatabaseStorage.CreateEmpty();
        }
        /// <inheritdoc />
        public void InstallDatabase()
        {
            // do nothing
        }
        /// <inheritdoc />
        public int GetEstimatedEntityCount()
        {
            return Storage.Entities.Count;
        }
        /// <inheritdoc />
        public IEnumerable<StoredSecurityEntity> LoadSecurityEntities()
        {
            return Storage.Entities.Values;
        }
        /// <inheritdoc />
        public IEnumerable<int> LoadAffectedEntityIdsByEntriesAndBreaks()
        {
            lock (AcesLock)
            {
                var byEntries = Storage.Aces.Select(a => a.EntityId);
                var byBreaks = Storage.Entities.Values.Where(e => e.IsInherited == false).Select(e => e.Id);
                var result = byEntries.Union(byBreaks).Distinct().ToArray();
                return result;
            }
        }
        /// <inheritdoc />
        public IEnumerable<SecurityGroup> LoadAllGroups()
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
            return groups.Values;
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
            lock (AcesLock)
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

        /// <inheritdoc />
        public StoredSecurityEntity LoadStoredSecurityEntity(int entityId)
        {
            Storage.Entities.TryGetValue(entityId, out var entity);
            return entity;
        }
        /// <inheritdoc />
        public void InsertSecurityEntity(StoredSecurityEntity entity)
        {
            var origEntity = LoadStoredSecurityEntity(entity.Id);
            if (origEntity != null)
                return;

            Storage.Entities[entity.Id] = entity;
        }
        /// <inheritdoc />
        public void UpdateSecurityEntity(StoredSecurityEntity entity)
        {
            var oldEntity = LoadStoredSecurityEntity(entity.Id);
            if (oldEntity == null)
                throw new EntityNotFoundException("Cannot update entity because it does not exist: " + entity.Id);
            Storage.Entities[entity.Id] = entity;
        }
        /// <inheritdoc />
        public void DeleteSecurityEntity(int entityId)
        {
            Storage.Entities.Remove(entityId);
        }
        /// <inheritdoc />
        public void MoveSecurityEntity(int sourceId, int targetId)
        {
            var source = LoadStoredSecurityEntity(sourceId);
            if (source == null)
                throw new EntityNotFoundException("Cannot execute the move operation because source does not exist: " + sourceId);
            var target = LoadStoredSecurityEntity(targetId);
            if (target == null)
                throw new EntityNotFoundException("Cannot execute the move operation because target does not exist: " + targetId);
            source.ParentId = target.Id;
        }

        /// <inheritdoc />
        public SecurityGroup LoadSecurityGroup(int groupId)
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
            return rows == 0 ? null : group;
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

        /// <inheritdoc />
        public IEnumerable<StoredAce> LoadAllPermissionEntries()
        {
            lock (AcesLock)
                return Storage.Aces.Select(x => x.Clone()).ToArray();
        }
        /// <inheritdoc />
        public IEnumerable<StoredAce> LoadPermissionEntries(IEnumerable<int> entityIds)
        {
            lock (AcesLock)
                return Storage.Aces.Where(a => entityIds.Contains(a.EntityId)).ToArray();
        }

        /// <inheritdoc />
        public void WritePermissionEntries(IEnumerable<StoredAce> aces)
        {
            lock (AcesLock)
            {
                foreach (var ace in aces)
                {
                    var old = Storage.Aces.FirstOrDefault(x => x.EntityId == ace.EntityId && x.EntryType == ace.EntryType && x.IdentityId == ace.IdentityId && x.LocalOnly == ace.LocalOnly);
                    if (old != null)
                        Storage.Aces.Remove(old);
                    Storage.Aces.Add(ace);
                }
            }
        }

        /// <inheritdoc />
        public void RemovePermissionEntries(IEnumerable<StoredAce> aces)
        {
            lock (AcesLock)
            {
                foreach (var ace in aces)
                {
                    var old = Storage.Aces.FirstOrDefault(x => x.EntityId == ace.EntityId && x.EntryType == ace.EntryType && x.IdentityId == ace.IdentityId && x.LocalOnly == ace.LocalOnly);
                    if (old != null)
                        Storage.Aces.Remove(old);
                }
            }
        }

        /// <inheritdoc />
        public void RemovePermissionEntriesByEntity(int entityId)
        {
            lock (AcesLock)
                Storage.Aces.RemoveAll(y => y.EntityId == entityId);
        }

        internal void RemovePermissionEntriesByGroup(int groupId)
        {
            lock (AcesLock)
                Storage.Aces.RemoveAll(x => x.IdentityId == groupId);
        }

        /// <inheritdoc />
        public void DeleteEntitiesAndEntries(int entityId)
        {
            lock (AcesLock)
                Storage.Aces.RemoveAll(y => y.EntityId == entityId);

            var childIds = Storage.Entities.Values.Where(se => se.ParentId == entityId).Select(sec => sec.Id).ToArray();

            // delete children recursively
            foreach (var childEntityId in childIds)
            {
                DeleteEntitiesAndEntries(childEntityId);
            }

            // remove the entity itself
            Storage.Entities.Remove(entityId);}

        /// <inheritdoc />
        public void QueryGroupRelatedEntities(int groupId, out IEnumerable<int> entityIds, out IEnumerable<int> exclusiveEntityIds)
        {
            lock (AcesLock)
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



        internal static int LastActivityId;

        /// <inheritdoc />
        public int SaveSecurityActivity(SecurityActivity activity, out int bodySize)
        {
            lock (MessageLock)
            {
                var id = Interlocked.Increment(ref LastActivityId);
                var body =  SecurityActivity.SerializeActivity(activity);
                bodySize = body.Length;
                Storage.Messages.Add(new Tuple<int, DateTime, byte[]>(id, DateTime.UtcNow, body));
                return id;
            }
        }

        /// <inheritdoc />
        public int GetLastSecurityActivityId(DateTime startedTime)
        {
            lock (MessageLock)
            {
                var lastMessage = Storage.Messages?.OrderByDescending(m => m.Item1).FirstOrDefault();
                return lastMessage?.Item1 ?? 0;
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
            lock (MessageLock)
            {
                var result = new List<SecurityActivity>();

                foreach (var (id, _, body) in Storage.Messages.Where(x => x.Item1 >= from && x.Item1 <= to).Take(count))
                {
                    var activity = SecurityActivity.DeserializeActivity(body);
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
            lock (MessageLock)
            {
                var result = new List<SecurityActivity>();

                foreach (var (id, _, body) in Storage.Messages.Where(x => gaps.Contains(x.Item1)))
                {
                    var activity = SecurityActivity.DeserializeActivity(body);
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
            lock (MessageLock)
            {
                var item = Storage.Messages.FirstOrDefault(x => x.Item1 == id);
                if (item == null)
                    return null;

                var activity = SecurityActivity.DeserializeActivity(item.Item3);
                activity.Id = item.Item1;
                return activity;
            }
        }

        /// <inheritdoc />
        public void CleanupSecurityActivities(int timeLimitInMinutes)
        {
            lock (MessageLock)
            {
                var timeLimit = DateTime.UtcNow.AddMinutes(-timeLimitInMinutes);

                foreach (var item in Storage.Messages.Where(x => x.Item2 < timeLimit).ToArray())
                    Storage.Messages.Remove(item);
            }
        }


        /// <inheritdoc />
        public Messaging.SecurityActivityExecutionLock AcquireSecurityActivityExecutionLock(SecurityActivity securityActivity, int timeoutInSeconds)
        {
            return new Messaging.SecurityActivityExecutionLock(securityActivity, true);
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
        public void DeleteIdentityAndRelatedEntries(int identityId)
        {
            Storage.Memberships.RemoveAll(m => m.GroupId == identityId || m.MemberId == identityId);
            RemovePermissionEntriesByGroup(identityId);
        }

        /// <inheritdoc />
        public void DeleteIdentitiesAndRelatedEntries(IEnumerable<int> ids)
        {
            foreach (var id in ids)
                DeleteIdentityAndRelatedEntries(id);
        }

        /// <inheritdoc />
        public void AddMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
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
        }

        /// <inheritdoc />
        public void RemoveMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            if (groupMembers != null)
                foreach (var memberId in groupMembers)
                    Storage.Memberships.RemoveAll(m => m.GroupId == groupId && m.MemberId == memberId);
            if (userMembers != null)
                foreach (var memberId in userMembers)
                    Storage.Memberships.RemoveAll(m => m.GroupId == groupId && m.MemberId == memberId);
        }


        //============================================================

        /// <inheritdoc />
        public IEnumerable<long> GetMembershipForConsistencyCheck()
        {
            return Storage.Memberships.Select(m => (Convert.ToInt64(m.GroupId) << 32) + m.MemberId).ToArray();
        }
    }
}
