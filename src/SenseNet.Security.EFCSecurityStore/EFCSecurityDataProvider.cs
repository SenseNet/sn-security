using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SqlClient;
using System.Linq;
using System.Threading;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;

// ReSharper disable InconsistentNaming
namespace SenseNet.Security.EFCSecurityStore
{
    /// <summary>
    /// An ISecurityDataProvider implementation built on top of Entity Framework.
    /// </summary>
    public class EFCSecurityDataProvider : ISecurityDataProvider
    {
        /// <summary>Initializes a new instance of the EFCSecurityDataProvider class.</summary>
        public EFCSecurityDataProvider() : this(0)
        {
        }
        /// <summary>Initializes a new instance of the EFCSecurityDataProvider class.</summary>
        public EFCSecurityDataProvider(int commandTimeout = 120, string connectionString = null)
        {
            // fallback to configuration
            if (commandTimeout == 0)
                commandTimeout = Configuration.Data.SecurityDatabaseCommandTimeoutInSeconds;

            // fallback to well-known connection strings if the caller did not provide one
            if (connectionString == null)
                connectionString = ConfigurationManager.ConnectionStrings["SecurityStorage"]?.ConnectionString ??
                                   ConfigurationManager.ConnectionStrings["SnCrMsSql"]?.ConnectionString;

            CommandTimeout = commandTimeout;
            ConnectionString = connectionString;
        }

        internal SecurityStorage Db()
        {
            return new SecurityStorage(this);
        }

        public void ConfigureStorage(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlServer(ConnectionString, p => p.CommandTimeout(CommandTimeout));
        }

        //===================================================================== interface implementation

        private int CommandTimeout { get; }

        /// <summary>
        /// Control data for building a connection to the database server.
        /// </summary>
        public string ConnectionString { get; set; }

        /// <summary>
        /// Creator method. Returns a brand new ISecurityDataProvider instance.
        /// </summary>
        public ISecurityDataProvider CreateNew()
        {
            return new EFCSecurityDataProvider(CommandTimeout, ConnectionString);
        }
        /// <summary>
        /// Empties the entire database (clears all records from all tables).
        /// </summary>
        public void DeleteEverything()
        {
            using (var db = Db())
            {
                db.CleanupDatabase();
            }
        }

        /// <summary>
        /// Creates the database schema and other components (tables, etc.). It requires an existing database.
        /// </summary>
        public void InstallDatabase()
        {
            using (var db = Db())
            {
                db.InstallDatabase();
            }
        }

        /// <summary>
        /// Returns with the estimated security entity count as fast as possible.
        /// System start sequence uses this method.
        /// </summary>
        public int GetEstimatedEntityCount()
        {
            using (var db = Db())
                return db.GetEstimatedEntityCount();
        }

        /// <summary>
        /// Preloader method for retrieving all stored SecurityEntity. Called during system start.
        /// </summary>
        public IEnumerable<StoredSecurityEntity> LoadSecurityEntities()
        {
            using (var db = Db())
            {
                return db.EFEntities.Select(x => new StoredSecurityEntity
                {
                    Id = x.Id,
                    nullableOwnerId = x.OwnerId,
                    nullableParentId = x.ParentId,
                    IsInherited = x.IsInherited
                }).ToArray();
            }
        }
        /// <summary>
        /// Loads the set of security holder entity ids.
        /// This is a distincted int list of entities in entries plus entities that are not inherited (IsInherited = false).
        /// </summary>
        public IEnumerable<int> LoadAffectedEntityIdsByEntriesAndBreaks()
        {
            using (var db = Db())
                return db.LoadAffectedEntityIdsByEntriesAndBreaks();
        }
        /// <summary>
        /// Loader method for retrieving all ACE-s. Called during system start.
        /// </summary>
        public IEnumerable<StoredAce> LoadAllAces()
        {
            using (var db = Db())
            {
                foreach (var dbItem in db.EFEntries)
                {
                    var item = dbItem.ToStoredAce();
                    yield return item;
                }
            }
        }

        /// <summary>
        /// Retrieves the SecurityEntity by the passed identifier. Returns with null if the entity was not found.
        /// </summary>
        public StoredSecurityEntity LoadStoredSecurityEntity(int entityId)
        {
            using (var db = Db())
                return db.LoadStoredSecurityEntityById(entityId);
        }
        /// <summary>
        /// Writes the given entity to the database. If it exists before writing, the operation will be skipped.
        /// </summary>
        public void InsertSecurityEntity(StoredSecurityEntity entity)
        {
            using (var db = Db())
            {
                var origEntity = LoadEFEntity(entity.Id, db);
                if (origEntity != null)
                    return;

                db.EFEntities.Add(new EFEntity
                {
                    Id = entity.Id,
                    OwnerId = entity.nullableOwnerId,
                    ParentId = entity.nullableParentId,
                    IsInherited = entity.IsInherited
                });
                try
                {
                    db.SaveChanges();
                }
                catch (DbUpdateException)
                {
                    // entity already exists, that's ok
                }
            }
        }
        /// <summary>
        /// Updates the given entity to the database. If it does not exist before updating, 
        /// a SecurityStructureException must be thrown.
        /// </summary>
        public void UpdateSecurityEntity(StoredSecurityEntity entity)
        {
            var exceptions = new List<Exception>();

            for (var retry = 3; retry > 0; retry--)
            {
                try
                {
                    using (var db = Db())
                    {
                        var oldEntity = LoadEFEntity(entity.Id, db);
                        if (oldEntity == null)
                            throw new EntityNotFoundException("Cannot update entity because it does not exist: " + entity.Id);

                        oldEntity.OwnerId = entity.nullableOwnerId;
                        oldEntity.ParentId = entity.nullableParentId;
                        oldEntity.IsInherited = entity.IsInherited;

                        db.SaveChanges();
                        return;
                    }
                }
                catch (DbUpdateConcurrencyException ex)
                {
                    // handling concurrency
                    exceptions.Add(ex);

                    // if this is not the last iteration, wait a bit before retrying
                    if (retry > 0)
                        Thread.Sleep(10);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);

                    // unknown exception: skip out of the loop immediately
                    break;
                }
            }

            // the loop was finished after several attenpts
            if (exceptions.Count > 0)
                throw new SecurityStructureException(
                    "Cannot update entity because of concurrency: " + entity.Id, new AggregateException(exceptions));
        }
        /// <summary>
        /// Deletes an entity by the given identifier. If the entity does not exist before deleting, this method does nothing.
        /// </summary>
        public void DeleteSecurityEntity(int entityId)
        {
            using (var db = Db())
            {
                var oldEntity = db.EFEntities.FirstOrDefault(x => x.Id == entityId);
                if (oldEntity == null)
                    return;
                db.EFEntities.Remove(oldEntity);
                try
                {
                    db.SaveChanges();
                }
                catch (DbUpdateConcurrencyException)
                {
                    // if someone else has already deleted this entity, do not throw an exception
                }
                catch (Exception ex)
                {
                    throw new SecurityStructureException("Cannot delete entity because of a database error: " + entityId, ex);
                }
            }
        }
        /// <summary>
        /// Moves the source entity to the target entity. Only a parent relink is needed. All other operations call 
        /// other data provider methods.
        /// </summary>
        public void MoveSecurityEntity(int sourceId, int targetId) // always called with SetSecurityHolder method
        {
            using (var db = Db())
            {
                var source = LoadEFEntity(sourceId, db);
                if (source == null)
                    throw new EntityNotFoundException(
                        "Cannot execute the move operation because source does not exist: " + sourceId);
                var target = LoadEFEntity(targetId, db);
                if (target == null)
                    throw new EntityNotFoundException(
                        "Cannot execute the move operation because target does not exist: " + targetId);

                source.ParentId = target.Id;

                db.SaveChanges();
            }
        }

        /// <summary>
        /// This method must return with all stored ACEs that exist in the database in an unordered list.
        /// </summary>
        public IEnumerable<StoredAce> LoadAllPermissionEntries()
        {
            using (var db = Db())
            {
                return db.EFEntries
                    .ToArray()  // entity framework does not know the ulong because it is dumb :(
                    .Select(a => new StoredAce
                    {
                        EntityId = a.EFEntityId,
                        EntryType = (EntryType)a.EntryType,
                        IdentityId = a.IdentityId,
                        LocalOnly = a.LocalOnly,
                        AllowBits = a.AllowBits.ToUInt64(),
                        DenyBits = a.DenyBits.ToUInt64()
                    })
                    .ToArray();
            }
        }
        /// <summary>
        /// Loads an ACL-chain. Caller provides the parent chain of an entity.
        /// This method must return with all stored ACEs that belong to any of the passed entity ids.
        /// Order is irrelevant.
        /// </summary>
        public IEnumerable<StoredAce> LoadPermissionEntries(IEnumerable<int> entityIds)
        {
            using (var db = Db())
            {
                return db.EFEntries
                    .Where(x => entityIds.Contains(x.EFEntityId))
                    .ToArray()  // entity framework does not know the ulong because it is dumb :(
                    .Select(a => new StoredAce
                    {
                        EntityId = a.EFEntityId,
                        EntryType = (EntryType)a.EntryType,
                        IdentityId = a.IdentityId,
                        LocalOnly = a.LocalOnly,
                        AllowBits = a.AllowBits.ToUInt64(),
                        DenyBits = a.DenyBits.ToUInt64()
                    })
                    .ToArray();
            }
        }
        /// <summary>
        /// Inserts or updates one or more StoredACEs.
        /// An ACE is identified by a compound key: EntityId, EntryType, IdentityId, LocalOnly
        /// </summary>
        public void WritePermissionEntries(IEnumerable<StoredAce> aces)
        {
            try
            {
                using (var db = Db())
                    // ReSharper disable once PossibleMultipleEnumeration
                    db.WritePermissionEntries(aces);
            }
            catch (SqlException ex)
            {
                // possible foreign key constraint error
                var message = ex.Message.StartsWith("The INSERT statement conflicted with the FOREIGN KEY constraint")
                    ? "Cannot write permission entries because one of the entities is missing from the database. " +
                        // ReSharper disable once PossibleMultipleEnumeration
                        string.Join(",", aces.Select(a => a.EntityId).Distinct().OrderBy(ei => ei))
                    : "Cannot write permission entries because of a database error.";

                throw new SecurityStructureException(message, ex);
            }
        }
        /// <summary>
        /// Deletes the given ACEs.  If an ACE does not exist before deleting, it must be skipped.
        /// An ACE is identified by a compound key: EntityId, EntryType, IdentityId, LocalOnly
        /// </summary>
        public void RemovePermissionEntries(IEnumerable<StoredAce> aces)
        {
            using (var db = Db())
                db.RemovePermissionEntries(aces);
        }
        /// <summary>
        /// Deletes all ACEs related to the given entity id.
        /// </summary>
        public void RemovePermissionEntriesByEntity(int entityId)
        {
            using (var db = Db())
                db.RemovePermissionEntriesByEntity(entityId);
        }
        /// <summary>
        /// Deletes all ACEs related to any of the entities in a subtree defined by the provided root id, then 
        /// deletes all the entities too.
        /// </summary>
        public void DeleteEntitiesAndEntries(int entityId)
        {
            using (var db = Db())
                db.DeleteEntitiesAndEntries(entityId);
        }

        //===================================================================== SecurityActivity

        /// <summary>
        /// Returns the biggest activity id that was saved before the provided time if there is any.
        /// Otherwise returns with 0.
        /// </summary>
        public int GetLastSecurityActivityId(DateTime startedTime)
        {
            using (var db = Db())
            {
                var lastMsg = db.EFMessages.OrderByDescending(e => e.Id).FirstOrDefault();
                return lastMsg?.Id ?? 0;
            }
        }

        /// <summary>
        /// Returns an array of all unprocessed activity ids supplemented with the last stored activity id.
        /// Empty array means that the database does not contain any activities.
        /// Array with only one element means that the database does not contain any unprocessed element 
        /// and the last stored activity id is the returned item.
        /// Two or more element means that the array contains one or more unprocessed activity id and the 
        /// last element is the last stored activity id.
        /// </summary>
        /// <returns>Zero or more id of unprocessed elements supplemented with the last stored activity id.</returns>
        public int[] GetUnprocessedActivityIds()
        {
            using (var db = Db())
            {
                return db.GetUnprocessedActivityIds();
            }
        }
        /// <summary>
        /// Loads a SecurityActivity fragment within the specified limits.
        /// If the count of activities in the id boundary ("from", "to") is bigger
        /// than the given fragment size ("count"), the largest id could not reach.
        /// Activities in the result array are sorted by id.
        /// Value of the IsUnprocessedActivity property of every loaded object
        /// vill be the value of the given "executingUnprocessedActivities" parameter.
        /// </summary>
        /// <param name="from">Least expected id.</param>
        /// <param name="to">Largest allowed id.</param>
        /// <param name="count">Fragment size.</param>
        /// <param name="executingUnprocessedActivities">
        /// Value of the IsUnprocessedActivity property of every loaded object.</param>
        public SecurityActivity[] LoadSecurityActivities(int from, int to, int count, bool executingUnprocessedActivities)
        {
            var result = new List<SecurityActivity>();
            using (var db = Db())
            {
                foreach (var item in db.EFMessages.Where(x => x.Id >= from && x.Id <= to).OrderBy(x => x.Id).Take(count))
                {
                    var activity = SecurityActivity.DeserializeActivity(item.Body);
                    if (activity == null)
                        continue;
                    activity.Id = item.Id;
                    activity.FromDatabase = true;
                    activity.IsUnprocessedActivity = executingUnprocessedActivities;
                    result.Add(activity);
                }
            }
            return result.ToArray();
        }
        /// <summary>
        /// Loads a SecurityActivity fragment by the individual id array.
        /// Activities in the result array are sorted by id.
        /// Value of the IsUnprocessedActivity property of every loaded object
        /// vill be the value of the given "executingUnprocessedActivities" parameter.
        /// </summary>
        /// <param name="gaps">Individual id array</param>
        /// <param name="executingUnprocessedActivities">
        /// Value of the IsUnprocessedActivity property of every loaded object.</param>
        public SecurityActivity[] LoadSecurityActivities(int[] gaps, bool executingUnprocessedActivities)
        {
            var result = new List<SecurityActivity>();
            using (var db = Db())
            {
                foreach (var item in db.EFMessages.Where(x => gaps.Contains(x.Id)).OrderBy(x => x.Id))
                {
                    var activity = SecurityActivity.DeserializeActivity(item.Body);
                    if (activity == null)
                        continue;
                    activity.Id = item.Id;
                    activity.FromDatabase = true;
                    activity.IsUnprocessedActivity = executingUnprocessedActivities;
                    result.Add(activity);
                }
            }
            return result.ToArray();
        }
        /// <summary>
        /// Returns a SecurityActivity.
        /// </summary>
        public SecurityActivity LoadSecurityActivity(int id)
        {
            using (var db = Db())
            {
                var item = db.EFMessages.FirstOrDefault(x => x.Id == id);
                if (item == null)
                    return null;

                var activity = SecurityActivity.DeserializeActivity(item.Body);
                activity.Id = item.Id;
                return activity;
            }
        }
        /// <summary>
        /// Stores the full data of the passed activity.
        /// Returns with the generated activity id and the size of the activity's body. 
        /// Activity ids in the database must be a consecutive list of numbers.
        /// </summary>
        /// <param name="activity">Activity to save.</param>
        /// <param name="bodySize">Activity size in bytes.</param>
        /// <returns>The generated activity id.</returns>
        public int SaveSecurityActivity(SecurityActivity activity, out int bodySize)
        {
            var body = SecurityActivity.SerializeActivity(activity);
            bodySize = body.Length;
            EntityEntry<EFMessage> result;
            using (var db = Db())
            {
                result = db.EFMessages.Add(new EFMessage
                {
                    ExecutionState = ExecutionState.Wait,
                    SavedBy = activity.Context.MessageProvider.ReceiverName,
                    SavedAt = DateTime.UtcNow,
                    Body = body
                });
                db.SaveChanges();
            }
            return result.Entity.Id;
        }
        /// <summary>
        /// Deletes all the activities that were saved before the given time limit.
        /// </summary>
        public void CleanupSecurityActivities(int timeLimitInMinutes)
        {
            using (var db = Db())
                db.CleanupSecurityActivities(timeLimitInMinutes);
        }

        /// <summary>
        /// Ensures an exclusive (only one) object for the activity. Returns the new lock object or null.
        /// </summary>
        public SecurityActivityExecutionLock AcquireSecurityActivityExecutionLock(
            SecurityActivity securityActivity, int timeoutInSeconds)
        {
            var maxTime = timeoutInSeconds == int.MaxValue ? DateTime.MaxValue : DateTime.UtcNow.AddSeconds(timeoutInSeconds);
            while (DateTime.UtcNow < maxTime)
            {
                string result;
                using (var db = Db())
                    result = db.AcquireSecurityActivityExecutionLock(
                        securityActivity.Id, securityActivity.Context.MessageProvider.ReceiverName, timeoutInSeconds);

                // ReSharper disable once SwitchStatementMissingSomeCases
                switch (result)
                {
                    case ExecutionState.LockedForYou:
                        // enable full executing
                        return new SecurityActivityExecutionLock(securityActivity, true);
                    case ExecutionState.Executing:
                    case ExecutionState.Done:
                        // enable partially executing
                        return new SecurityActivityExecutionLock(securityActivity, false);
                }
            }
            throw new SecurityActivityTimeoutException(
                $"Waiting for a SecurityActivityExecutionLock timed out: #{securityActivity.Id}/{securityActivity.TypeName}");
        }
        /// <summary>
        /// Refreshes the lock object to avoid its timeout.
        /// </summary>
        public void RefreshSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            using (var db = Db())
                db.RefreshSecurityActivityExecutionLock(securityActivity.Id);
        }
        /// <summary>
        /// Releases the lock and prevents locking that activity again by setting its state to Executed.
        /// </summary>
        public void ReleaseSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            using (var db = Db())
                db.ReleaseSecurityActivityExecutionLock(securityActivity.Id);
        }

        //===================================================================== Tools

        private EFEntity LoadEFEntity(int entityId, SecurityStorage db)
        {
            return db.EFEntities.FirstOrDefault(x => x.Id == entityId);
        }

        /* ===================================================================== */

        /// <summary>
        /// This method provides a collection of entity ids that have a group-related access control entry.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="entityIds">
        /// Entities that have one or more group related ACEs. These ACEs will be removed from the ACLs. </param>
        /// <param name="exclusiveEntityIds">
        /// Entities that have only the given group related ACEs. These ACLs will be removed. </param>
        public void QueryGroupRelatedEntities(
            int groupId, out IEnumerable<int> entityIds, out IEnumerable<int> exclusiveEntityIds)
        {
            var result = new List<int>();
            using (var db = Db())
            {
                entityIds = db.EFEntries.Where(x => x.IdentityId == groupId).Select(x => x.EFEntityId).Distinct().ToArray();
                foreach (var relatedEntityId in entityIds)
                {
                    var aces = db.EFEntries.Where(x => x.EFEntityId == relatedEntityId).ToArray();
                    var groupRelatedCount = aces.Count(x => x.IdentityId == groupId);
                    if (aces.Length == groupRelatedCount)
                        result.Add(relatedEntityId);
                }
            }
            exclusiveEntityIds = result;
        }


        /******************************************* membership storage */

        /// <summary>
        /// Preloader method for retrieving all stored SecurityGroups. Called during system start.
        /// </summary>
        public IEnumerable<SecurityGroup> LoadAllGroups()
        {
            var groups = new Dictionary<int, SecurityGroup>();
            using (var db = Db())
            {
                foreach (var membership in db.EFMemberships)
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
            }
            return groups.Values;
        }
        private SecurityGroup EnsureGroup(int groupId, Dictionary<int, SecurityGroup> groups)
        {
            if (groups.TryGetValue(groupId, out var group))
                return group;
            group = new SecurityGroup(groupId);
            groups.Add(group.Id, group);
            return group;
        }

        /// <summary>
        /// Loads a SecurityGroup from the database.
        /// </summary>
        public SecurityGroup LoadSecurityGroup(int groupId)
        {
            var group = new SecurityGroup(groupId);
            var groups = new Dictionary<int, SecurityGroup> { { group.Id, group } };
            var rows = 0;
            using (var db = Db())
            {
                foreach (var membership in db.EFMemberships.Where(x => x.GroupId == groupId))
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
            }
            return rows == 0 ? null : group;
        }

        /// <summary>
        /// Deletes memberships and entries related to an identity.
        /// </summary>
        public void DeleteIdentityAndRelatedEntries(int identityId)
        {
            using (var db = Db())
                db.DeleteIdentity(identityId);
        }

        /// <summary>
        /// Deletes memberships and entries related to the provided identities.
        /// </summary>
        public void DeleteIdentitiesAndRelatedEntries(IEnumerable<int> ids)
        {
            using (var db = Db())
                db.DeleteIdentities(ids);
        }

        /// <summary>
        /// Adds one or more users and groups to the specified group.
        /// </summary>
        /// <param name="groupId">Id of the group that will have new members.</param>
        /// <param name="userMembers">Contains the ids of new users. Can be null or an empty list too.</param>
        /// <param name="groupMembers">Contains the ids of new groups. Can be null or an empty list too.</param>
        public void AddMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            groupMembers = groupMembers ?? new int[0];
            userMembers = userMembers ?? new int[0];

            var groupArray = groupMembers as int[] ?? groupMembers.ToArray();
            var userArray = userMembers as int[] ?? userMembers.ToArray();

            var allNewMembers = groupArray.Union(userArray);
            using (var db = Db())
            {
                var origMemberIds = db.EFMemberships
                    .Where(m => m.GroupId == groupId && allNewMembers.Contains(m.MemberId))
                    .Select(m => m.MemberId)
                    .ToArray();
                var newGroupIds = groupArray.Except(origMemberIds).ToArray();
                var newUserIds = userArray.Except(origMemberIds).ToArray();
                var newGroups = newGroupIds.Select(g => new EFMembership { GroupId = groupId, MemberId = g, IsUser = false });
                var newUsers = newUserIds.Select(g => new EFMembership { GroupId = groupId, MemberId = g, IsUser = true });

                db.EFMemberships.AddRange(newGroups);
                db.EFMemberships.AddRange(newUsers);

                db.SaveChanges();
            }
        }

        /// <summary>
        /// Removes one or more users and groups from the specified group.
        /// </summary>
        /// <param name="groupId">Id of a group.</param>
        /// <param name="userMembers">
        /// Contains the ids of users that will be removed. Can be null or an empty list too.</param>
        /// <param name="groupMembers">
        /// Contains the ids of groups that will be removed. Can be null or an empty list too.</param>
        public void RemoveMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            using (var db = Db())
                db.RemoveMembers(groupId, userMembers ?? new int[0], groupMembers ?? new int[0]);
        }


        //============================================================

        /// <summary>
        /// Returns with information for consistency check: a compound number containing the group's and the member's id.
        /// </summary>
        public IEnumerable<long> GetMembershipForConsistencyCheck()
        {
            using (var db = Db())
                return db.EFMemberships.AsEnumerable().Select(m => (Convert.ToInt64(m.GroupId) << 32) + m.MemberId).ToArray();
        }
    }
}
