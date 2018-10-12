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
    public class MemoryDataProvider : ISecurityDataProvider
    {
        private static readonly object MessageLock = new object();
        private static readonly object AcesLock = new object();

        private static DatabaseStorage _storage;
        internal static DatabaseStorage Storage { get { return _storage; } }

        private MemoryDataProvider()
        {
        }

        /// <inheritdoc />
        public MemoryDataProvider(DatabaseStorage storage)
        {
            _storage = storage;
        }

        /* ===================================================================== interface implementation */

        //it is not used
        /// <inheritdoc />
        public string ConnectionString { get; set; }

        /// <inheritdoc />
        public virtual ISecurityDataProvider CreateNew()
        {
            return new MemoryDataProvider();
        }
        /// <inheritdoc />
        public void DeleteEverything()
        {
            _storage = DatabaseStorage.CreateEmpty();
        }
        /// <inheritdoc />
        public void InstallDatabase()
        {
            // do nothing
        }
        /// <inheritdoc />
        public int GetEstimatedEntityCount()
        {
            return _storage.Entities.Count;
        }
        /// <inheritdoc />
        public IEnumerable<StoredSecurityEntity> LoadSecurityEntities()
        {
            return _storage.Entities.Values;
        }
        /// <inheritdoc />
        public IEnumerable<int> LoadAffectedEntityIdsByEntriesAndBreaks()
        {
            lock (AcesLock)
            {
                var byEntries = _storage.Aces.Select(a => a.EntityId);
                var byBreaks = _storage.Entities.Values.Where(e => e.IsInherited == false).Select(e => e.Id);
                var result = byEntries.Union(byBreaks).Distinct().ToArray();
                return result;
            }
        }
        /// <inheritdoc />
        public IEnumerable<SecurityGroup> LoadAllGroups()
        {
            var groups = new Dictionary<int, SecurityGroup>();
            foreach (var membership in _storage.Memberships)
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
                foreach (var dbItem in _storage.Aces)
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
            _storage.Entities.TryGetValue(entityId, out var entity);
            return entity;
        }
        /// <inheritdoc />
        public void InsertSecurityEntity(StoredSecurityEntity entity)
        {
            var origEntity = LoadStoredSecurityEntity(entity.Id);
            if (origEntity != null)
                return;

            _storage.Entities[entity.Id] = entity;
        }
        /// <inheritdoc />
        public void UpdateSecurityEntity(StoredSecurityEntity entity)
        {
            var oldEntity = LoadStoredSecurityEntity(entity.Id);
            if (oldEntity == null)
                throw new EntityNotFoundException("Cannot update entity because it does not exist: " + entity.Id);
            _storage.Entities[entity.Id] = entity;
        }
        /// <inheritdoc />
        public void DeleteSecurityEntity(int entityId)
        {
            _storage.Entities.Remove(entityId);
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
            foreach (var membership in _storage.Memberships.Where(x => x.GroupId == groupId))
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
                return _storage.Aces.Select(x => x.Clone()).ToArray();
        }
        /// <inheritdoc />
        public IEnumerable<StoredAce> LoadPermissionEntries(IEnumerable<int> entityIds)
        {
            lock (AcesLock)
                return _storage.Aces.Where(a => entityIds.Contains(a.EntityId)).ToArray();
        }

        /// <inheritdoc />
        public void WritePermissionEntries(IEnumerable<StoredAce> aces)
        {
            lock (AcesLock)
            {
                foreach (var ace in aces)
                {
                    var old = _storage.Aces.FirstOrDefault(x => x.EntityId == ace.EntityId && x.EntryType == ace.EntryType && x.IdentityId == ace.IdentityId && x.LocalOnly == ace.LocalOnly);
                    if (old != null)
                        _storage.Aces.Remove(old);
                    _storage.Aces.Add(ace);
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
                    var old = _storage.Aces.FirstOrDefault(x => x.EntityId == ace.EntityId && x.EntryType == ace.EntryType && x.IdentityId == ace.IdentityId && x.LocalOnly == ace.LocalOnly);
                    if (old != null)
                        _storage.Aces.Remove(old);
                }
            }
        }

        /// <inheritdoc />
        public void RemovePermissionEntriesByEntity(int entityId)
        {
            lock (AcesLock)
                _storage.Aces.RemoveAll(y => y.EntityId == entityId);
        }

        internal void RemovePermissionEntriesByGroup(int groupId)
        {
            lock (AcesLock)
                _storage.Aces.RemoveAll(x => x.IdentityId == groupId);
        }

        /// <inheritdoc />
        public void DeleteEntitiesAndEntries(int entityId)
        {
            lock (AcesLock)
                _storage.Aces.RemoveAll(y => y.EntityId == entityId);

            var childIds = _storage.Entities.Values.Where(se => se.ParentId == entityId).Select(sec => sec.Id).ToArray();

            // delete children recursively
            foreach (var childEntityId in childIds)
            {
                DeleteEntitiesAndEntries(childEntityId);
            }

            // remove the entity itself
            _storage.Entities.Remove(entityId);}

        /// <inheritdoc />
        public void QueryGroupRelatedEntities(int groupId, out IEnumerable<int> entityIds, out IEnumerable<int> exclusiveEntityIds)
        {
            lock (AcesLock)
            {
                var result = new List<int>();
                entityIds = _storage.Aces.Where(x => x.IdentityId == groupId).Select(x => x.EntityId).Distinct();
                foreach (var relatedEntityId in entityIds)
                {
                    var aces = _storage.Aces.Where(x => x.EntityId == relatedEntityId).ToArray();
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
                _storage.Messages.Add(new Tuple<int, DateTime, byte[]>(id, DateTime.UtcNow, body));
                return id;
            }
        }

        /// <inheritdoc />
        public int GetLastSecurityActivityId(DateTime startedTime)
        {
            lock (MessageLock)
            {
                var lastMessage = _storage.Messages?.OrderByDescending(m => m.Item1).FirstOrDefault();
                if (lastMessage == null)
                    return 0;
                return lastMessage.Item1;
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

                foreach (var item in _storage.Messages.Where(x => x.Item1 >= from && x.Item1 <= to).Take(count))
                {
                    var activity = SecurityActivity.DeserializeActivity(item.Item3);
                    if (activity == null)
                        continue;
                    activity.Id = item.Item1;
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

                foreach (var item in _storage.Messages.Where(x => gaps.Contains(x.Item1)))
                {
                    var activity = SecurityActivity.DeserializeActivity(item.Item3);
                    if (activity == null)
                        continue;
                    activity.Id = item.Item1;
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
                var item = _storage.Messages.FirstOrDefault(x => x.Item1 == id);
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

                foreach (var item in _storage.Messages.Where(x => x.Item2 < timeLimit).ToArray())
                    _storage.Messages.Remove(item);
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
            _storage.Memberships.RemoveAll(m => (m.GroupId == identityId || m.MemberId == identityId));
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
                    _storage.Memberships.RemoveAll(m => m.GroupId == groupId && m.MemberId == memberId);
                    _storage.Memberships.Add(new Membership { GroupId = groupId, MemberId = memberId, IsUser = false });
                }
            }
            if (userMembers != null)
            {
                foreach (var memberId in userMembers)
                {
                    _storage.Memberships.RemoveAll(m => m.GroupId == groupId && m.MemberId == memberId);
                    _storage.Memberships.Add(new Membership { GroupId = groupId, MemberId = memberId, IsUser = true });
                }
            }
        }

        /// <inheritdoc />
        public void RemoveMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            if (groupMembers != null)
                foreach (var memberId in groupMembers)
                    _storage.Memberships.RemoveAll(m => m.GroupId == groupId && m.MemberId == memberId);
            if (userMembers != null)
                foreach (var memberId in userMembers)
                    _storage.Memberships.RemoveAll(m => m.GroupId == groupId && m.MemberId == memberId);
        }


        //============================================================

        /// <inheritdoc />
        public IEnumerable<long> GetMembershipForConsistencyCheck()
        {
            return _storage.Memberships.Select(m => (Convert.ToInt64(m.GroupId) << 32) + m.MemberId).ToArray();
        }
    }
}
