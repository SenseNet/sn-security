using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Data
{
    /// <summary>
    /// Complete ISecurityDataProvider implementation only for testing purposes.
    /// </summary>
    public class MemoryDataProvider : ISecurityDataProvider
    {
        private static object _messageLock = new object();
        private static object _acesLock = new object();

        private static DatabaseStorage _storage;
        internal static DatabaseStorage Storage { get { return _storage; } }

        private MemoryDataProvider()
        {
        }
        public MemoryDataProvider(DatabaseStorage storage)
        {
            _storage = storage;
        }

        //===================================================================== interface implementation

        //it is not used
        public string ConnectionString { get; set; }

        public virtual ISecurityDataProvider CreateNew()
        {
            return new MemoryDataProvider();
        }
        public void DeleteEverything()
        {
            _storage = DatabaseStorage.CreateEmpty();
        }
        public void InstallDatabase()
        {
            // do nothing
        }
        public int GetEstimatedEntityCount()
        {
            return _storage.Entities.Count;
        }
        public IEnumerable<StoredSecurityEntity> LoadSecurityEntities()
        {
            return _storage.Entities.Values;
        }
        public IEnumerable<int> LoadAffectedEntityIdsByEntriesAndBreaks()
        {
            lock (_acesLock)
            {
                var byEntries = _storage.Aces.Select(a => a.EntityId);
                var byBreaks = _storage.Entities.Values.Where(e => e.IsInherited == false).Select(e => e.Id);
                var result = byEntries.Union(byBreaks).Distinct().ToArray();
                return result;
            }
        }
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
            SecurityGroup group;
            if (!groups.TryGetValue(groupId, out group))
            {
                group = new SecurityGroup(groupId);
                groups.Add(group.Id, group);
            }
            return group;
        }

        public IEnumerable<StoredAce> LoadAllAces()
        {
            lock (_acesLock)
            {
                foreach (var dbItem in _storage.Aces)
                {
                    // return with a copy
                    yield return new StoredAce
                    {
                        EntityId = dbItem.EntityId,
                        IdentityId = dbItem.IdentityId,
                        LocalOnly = dbItem.LocalOnly,
                        AllowBits = dbItem.AllowBits,
                        DenyBits = dbItem.DenyBits
                    };
                }
            }
        }

        public StoredSecurityEntity LoadStoredSecurityEntity(int entityId)
        {
            StoredSecurityEntity entity;
            _storage.Entities.TryGetValue(entityId, out entity);
            return entity;
        }
        public void InsertSecurityEntity(StoredSecurityEntity entity)
        {
            var origEntity = LoadStoredSecurityEntity(entity.Id);
            if (origEntity != null)
                return;

            _storage.Entities[entity.Id] = entity;
        }
        public void UpdateSecurityEntity(StoredSecurityEntity entity)
        {
            var oldEntity = LoadStoredSecurityEntity(entity.Id);
            if (oldEntity == null)
                throw new EntityNotFoundException("Cannot update entity because it does not exist: " + entity.Id);
            _storage.Entities[entity.Id] = entity;
        }
        public void DeleteSecurityEntity(int entityId)
        {
            _storage.Entities.Remove(entityId);
        }
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

        public SecurityGroup LoadSecurityGroup(int groupId)
        {
            var group = new SecurityGroup(groupId);
            var groups = new Dictionary<int, SecurityGroup>();
            groups.Add(group.Id, group);
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

        public IEnumerable<StoredAce> LoadAllPermissionEntries()
        {
            lock (_acesLock)
                return _storage.Aces.Select(x => x.Clone()).ToArray();
        }
        public IEnumerable<StoredAce> LoadPermissionEntries(IEnumerable<int> entityIds)
        {
            lock (_acesLock)
                return _storage.Aces.Where(a => entityIds.Contains(a.EntityId)).ToArray();
        }

        public IEnumerable<StoredAce> LoadDescendantAces(int entityId, IEnumerable<int> identities)
        {
            return new StoredAceEnumerable(entityId, identities);
        }

        public void WritePermissionEntries(IEnumerable<StoredAce> aces)
        {
            lock (_acesLock)
            {
                foreach (var ace in aces)
                {
                    var old = _storage.Aces.Where(x => x.EntityId == ace.EntityId && x.IdentityId == ace.IdentityId && x.LocalOnly == ace.LocalOnly).FirstOrDefault();
                    if (old != null)
                        _storage.Aces.Remove(old);
                    _storage.Aces.Add(ace);
                }
            }
        }

        public void RemovePermissionEntries(IEnumerable<StoredAce> aces)
        {
            lock (_acesLock)
            {
                foreach (var ace in aces)
                {
                    var old = _storage.Aces.Where(x => x.EntityId == ace.EntityId && x.IdentityId == ace.IdentityId && x.LocalOnly == ace.LocalOnly).FirstOrDefault();
                    if (old != null)
                        _storage.Aces.Remove(old);
                }
            }
        }

        public void RemovePermissionEntriesByEntity(int entityId)
        {
            lock (_acesLock)
                _storage.Aces.RemoveAll(y => y.EntityId == entityId);
        }
        
        public void RemovePermissionEntriesByGroup(int groupId)
        {
            lock (_acesLock)
                _storage.Aces.RemoveAll(x => x.IdentityId == groupId);
        }

        public void DeleteEntitiesAndEntries(int entityId)
        {
            lock (_acesLock)
                _storage.Aces.RemoveAll(y => y.EntityId == entityId);

            var childIds = _storage.Entities.Values.Where(se => se.ParentId == entityId).Select(sec => sec.Id).ToArray();

            // delete children recursively
            foreach (var childEntityId in childIds)
            {
                DeleteEntitiesAndEntries(childEntityId);
            }

            // remove the entity itself
            _storage.Entities.Remove(entityId);}

        public IEnumerable<int> GetEntitiesOfGroup(int groupId)
        {
            lock (_acesLock)
            {
                //UNDONE:! check based on EF6 solution
                var result = new List<int>();
                var relatedEntityIds = _storage.Aces.Where(x => x.IdentityId == groupId).Select(x => x.EntityId).Distinct();
                return result;
            }
        }

        public void QueryGroupRelatedEntities(int groupId, out IEnumerable<int> entityIds, out IEnumerable<int> exclusiveEntityIds)
        {
            lock (_acesLock)
            {
                var result = new List<int>();
                entityIds = _storage.Aces.Where(x => x.IdentityId == groupId).Select(x => x.EntityId).Distinct();
                foreach (var relatedEntityId in entityIds)
                {
                    var aces = _storage.Aces.Where(x => x.EntityId == relatedEntityId).ToArray();
                    var groupRelatedCount = aces.Where(x => x.IdentityId == groupId).Count();
                    if (aces.Length == groupRelatedCount)
                        result.Add(relatedEntityId);
                }
                exclusiveEntityIds = result;
            }
        }



        internal static int LastActivityId;

        public int SaveSecurityActivity(SecurityActivity activity, out int bodySize)
        {
            lock (_messageLock)
            {
                var id = Interlocked.Increment(ref LastActivityId);
                var body =  SecurityActivity.SerializeActivity(activity);
                bodySize = body.Length;
                _storage.Messages.Add(new Tuple<int, DateTime, byte[]>(id, DateTime.UtcNow, body));
                return id;
            }
        }

        public int GetLastSecurityActivityId(DateTime startedTime)
        {
            lock (_messageLock)
            {
                if (_storage.Messages == null)
                    return 0;
                var lastMessage = _storage.Messages.OrderByDescending(m => m.Item1).FirstOrDefault();
                if (lastMessage == null)
                    return 0;
                return lastMessage.Item1;
            }
        }

        public int[] GetUnprocessedActivityIds()
        {
            return new[] { 0 };
        }

        public SecurityActivity[] LoadSecurityActivities(int from, int to, int count, bool executingUnprocessedActivities)
        {
            lock (_messageLock)
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

        public SecurityActivity[] LoadSecurityActivities(int[] gaps, bool executingUnprocessedActivities)
        {
            lock (_messageLock)
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

        public virtual SecurityActivity LoadSecurityActivity(int id)
        {
            lock (_messageLock)
            {
                var item = _storage.Messages.Where(x => x.Item1 == id).FirstOrDefault();
                if (item == null)
                    return null;

                var activity = SecurityActivity.DeserializeActivity(item.Item3);
                activity.Id = item.Item1;
                return activity;
            }
        }

        public void CleanupSecurityActivities(int timeLimitInMinutes)
        {
            lock (_messageLock)
            {
                var timeLimit = DateTime.UtcNow.AddMinutes(-timeLimitInMinutes);

                foreach (var item in _storage.Messages.Where(x => x.Item2 < timeLimit).ToArray())
                    _storage.Messages.Remove(item);
            }
        }


        public Messaging.SecurityActivityExecutionLock AcquireSecurityActivityExecutionLock(SecurityActivity securityActivity, int timeoutInSeconds)
        {
            return new Messaging.SecurityActivityExecutionLock(securityActivity, true);
        }
        public void RefreshSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            // do nothing
        }
        public void ReleaseSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            // do nothing
        }


        private class StoredAceEnumerable : IEnumerable<StoredAce>
        {
            int _entityId;
            IEnumerable<int> _identities;
            List<StoredAce> _aces = new List<StoredAce>();

            internal StoredAceEnumerable(int entityId, IEnumerable<int> identities)
            {
                _entityId = entityId;
                _identities = identities;
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }
            public IEnumerator<StoredAce> GetEnumerator()
            {
                var entity = _storage.Entities[_entityId];
                FindAces(entity);
                return _aces.GetEnumerator();
            }
            private void FindAces(StoredSecurityEntity entity)
            {
                lock (_acesLock)
                {
                    foreach (var child in _storage.Entities.Values.Where(e => e.ParentId == entity.Id).ToArray())
                        FindAces(child);
                    _aces.AddRange(_storage.Aces.Where(a => a.EntityId == entity.Id));
                }
            }
        }



        //TODO: thread safety
        public void DeleteIdentityAndRelatedEntries(int identityId)
        {
            _storage.Memberships.RemoveAll(m => (m.GroupId == identityId || m.MemberId == identityId));
            RemovePermissionEntriesByGroup(identityId);
        }

        public void DeleteIdentitiesAndRelatedEntries(IEnumerable<int> ids)
        {
            ids.Where(x => { DeleteIdentityAndRelatedEntries(x); return false; });
        }

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

        public IEnumerable<long> GetMembershipForConsistencyCheck()
        {
            return _storage.Memberships.Select(m => (Convert.ToInt64(m.GroupId) << 32) + m.MemberId).ToArray();
        }
    }
}
