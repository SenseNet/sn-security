﻿using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Data.SqlClient;
using System.Linq;
using System.Threading;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SenseNet.Security.EFCSecurityStore.Configuration;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

// ReSharper disable InconsistentNaming
namespace SenseNet.Security.EFCSecurityStore
{
    /// <summary>
    /// An ISecurityDataProvider implementation built on top of Entity Framework.
    /// </summary>
    public class EFCSecurityDataProvider : ISecurityDataProvider
    {
        private readonly DataOptions _options;
        private readonly ILogger<EFCSecurityDataProvider> _logger;
        private readonly IMessageSenderManager _messageSenderManager;

        /// <summary>Initializes a new instance of the EFCSecurityDataProvider class.</summary>
        [Obsolete("Use the constructor with IOptions and dependency injection instead.")]
        public EFCSecurityDataProvider(IMessageSenderManager messageSenderManager) : this(messageSenderManager, 0, null)
        {
        }
        /// <summary>Initializes a new instance of the EFCSecurityDataProvider class.</summary>
        [Obsolete("Use the constructor with IOptions and dependency injection instead.")]
        public EFCSecurityDataProvider(IMessageSenderManager messageSenderManager, int commandTimeout, string connectionString)
        {
            _messageSenderManager = messageSenderManager;

            // fallback to configuration
            if (commandTimeout == 0)
                commandTimeout = Configuration.Data.SecurityDatabaseCommandTimeoutInSeconds;

            // fallback to well-known connection strings if the caller did not provide one
            if (connectionString == null)
                connectionString = ConfigurationManager.ConnectionStrings["SecurityStorage"]?.ConnectionString ??
                                   ConfigurationManager.ConnectionStrings["SnCrMsSql"]?.ConnectionString;

            _options = new DataOptions
            {
                ConnectionString = connectionString,
                SqlCommandTimeout = commandTimeout
            };
            _logger = NullLogger<EFCSecurityDataProvider>.Instance;
        }
        /// <summary>Initializes a new instance of the EFCSecurityDataProvider class.</summary>
        public EFCSecurityDataProvider(IMessageSenderManager messageSenderManager, IOptions<DataOptions> options, ILogger<EFCSecurityDataProvider> logger)
        {
            _messageSenderManager = messageSenderManager;

            _options = options?.Value ?? new DataOptions();
            _logger = logger;

            if (string.IsNullOrEmpty(_options.ConnectionString))
                _logger.LogError("No connection string was configured for the security database.");
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

        private int CommandTimeout => _options.SqlCommandTimeout;

        /// <summary>
        /// Control data for building a connection to the database server.
        /// </summary>
        public string ConnectionString
        {
            get => _options.ConnectionString;
            set => _options.ConnectionString = value;
        }

        public IActivitySerializer ActivitySerializer { get; set; }

        /// <summary>
        /// Creates the database schema and other components (tables, etc.). It requires an existing database.
        /// </summary>
        public void InstallDatabase()
        {
            using var db = Db();
            db.InstallDatabase();
        }
        public async Task<bool> IsDatabaseReadyAsync(CancellationToken cancel)
        {
            const string schemaCheckSql = @"
SELECT CASE WHEN EXISTS (
    SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = N'EFEntries'
)
THEN CAST(1 AS BIT)
ELSE CAST(0 AS BIT) END";

            try
            {
                using var db = Db();
                using var conn = db.Database.GetDbConnection();
                await conn.OpenAsync(cancel).ConfigureAwait(false);

                using var cmd = conn.CreateCommand();
                cmd.CommandType = System.Data.CommandType.Text;
                cmd.CommandText = schemaCheckSql;

                var result = await cmd.ExecuteScalarAsync(cancel).ConfigureAwait(false);

                return Convert.ToBoolean(result);
            }
            catch (Exception ex)
            {
                _logger.LogTrace($"Error when accessing the database: {ex.Message}");
            }

            return false;
        }

        public int GetEstimatedEntityCount()
        {
            return GetEstimatedEntityCountAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<int> GetEstimatedEntityCountAsync(CancellationToken cancel)
        {
            await using var db = Db();
            return await db.GetEstimatedEntityCountAsync(cancel);
        }

        [Obsolete("Use async version instead.", true)]
        public IEnumerable<StoredSecurityEntity> LoadSecurityEntities()
        {
            return LoadSecurityEntitiesAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<IEnumerable<StoredSecurityEntity>> LoadSecurityEntitiesAsync(CancellationToken cancel)
        {
            await using var db = Db();
            return await db.EFEntities.Select(x => new StoredSecurityEntity
            {
                Id = x.Id,
                nullableOwnerId = x.OwnerId,
                nullableParentId = x.ParentId,
                IsInherited = x.IsInherited
            }).ToArrayAsync(cancel);
        }

        [Obsolete("Use async version instead.", true)]
        public IEnumerable<int> LoadAffectedEntityIdsByEntriesAndBreaks()
        {
            return LoadAffectedEntityIdsByEntriesAndBreaksAsync(CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<IEnumerable<int>> LoadAffectedEntityIdsByEntriesAndBreaksAsync(CancellationToken cancel)
        {
            await using var db = Db();
            return await db.LoadAffectedEntityIdsByEntriesAndBreaksAsync(cancel);
        }

        /// <summary>
        /// Loader method for retrieving all ACE-s. Called during system start.
        /// </summary>
        public IEnumerable<StoredAce> LoadAllAces()
        {
            using var db = Db();
            foreach (var dbItem in db.EFEntries)
            {
                var item = dbItem.ToStoredAce();
                yield return item;
            }
        }

        [Obsolete("Use async version instead.", true)]
        public StoredSecurityEntity LoadStoredSecurityEntity(int entityId)
        {
            return LoadStoredSecurityEntityAsync(entityId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<StoredSecurityEntity> LoadStoredSecurityEntityAsync(int entityId, CancellationToken cancel)
        {
            await using var db = Db();
            return await db.LoadStoredSecurityEntityByIdAsync(entityId, cancel);
        }

        [Obsolete("Use async version instead.", true)]
        public void InsertSecurityEntity(StoredSecurityEntity entity)
        {
            InsertSecurityEntityAsync(entity, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task InsertSecurityEntityAsync(StoredSecurityEntity entity, CancellationToken cancel)
        {
            using var db = Db();
            var origEntity = await LoadEFEntityAsync(entity.Id, db, cancel);
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
                await db.SaveChangesAsync(cancel);
            }
            catch (DbUpdateException)
            {
                // entity already exists, that's ok
            }
        }

        [Obsolete("Use async version instead.", true)]
        public void UpdateSecurityEntity(StoredSecurityEntity entity)
        {
            UpdateSecurityEntityAsync(entity, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task UpdateSecurityEntityAsync(StoredSecurityEntity entity, CancellationToken cancel)
        {
            var exceptions = new List<Exception>();

            for (var retry = 3; retry > 0; retry--)
            {
                try
                {
                    await using var db = Db();
                    var oldEntity = await LoadEFEntityAsync(entity.Id, db, cancel);
                    if (oldEntity == null)
                        throw new EntityNotFoundException("Cannot update entity because it does not exist: " + entity.Id);

                    oldEntity.OwnerId = entity.nullableOwnerId;
                    oldEntity.ParentId = entity.nullableParentId;
                    oldEntity.IsInherited = entity.IsInherited;

                    await db.SaveChangesAsync(cancel);
                    return;
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

            // the loop was finished after several attempts
            if (exceptions.Count > 0)
                throw new SecurityStructureException(
                    "Cannot update entity because of concurrency: " + entity.Id, new AggregateException(exceptions));
        }

        [Obsolete("Use async version instead.", true)]
        public void DeleteSecurityEntity(int entityId)
        {
            DeleteSecurityEntityAsync(entityId, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task DeleteSecurityEntityAsync(int entityId, CancellationToken cancel)
        {
            await using var db = Db();
            var oldEntity = db.EFEntities.FirstOrDefault(x => x.Id == entityId);
            if (oldEntity == null)
                return;
            db.EFEntities.Remove(oldEntity);
            try
            {
                await db.SaveChangesAsync(cancel);
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

        [Obsolete("Use async version instead.", true)]
        public void MoveSecurityEntity(int sourceId, int targetId) // always called with SetSecurityHolder method
        {
            MoveSecurityEntityAsync(sourceId, targetId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task MoveSecurityEntityAsync(int sourceId, int targetId, CancellationToken cancel) // always called with SetSecurityHolder method
        {
            await using var db = Db();
            var source = await LoadEFEntityAsync(sourceId, db, cancel);
            if (source == null)
                throw new EntityNotFoundException(
                    "Cannot execute the move operation because source does not exist: " + sourceId);
            var target = await LoadEFEntityAsync(targetId, db, cancel);
            if (target == null)
                throw new EntityNotFoundException(
                    "Cannot execute the move operation because target does not exist: " + targetId);

            source.ParentId = target.Id;

            await db.SaveChangesAsync(cancel);
        }

        [Obsolete("Use async version instead.", true)]
        public IEnumerable<StoredAce> LoadAllPermissionEntries()
        {
            return LoadAllPermissionEntriesAsync(CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<IEnumerable<StoredAce>> LoadAllPermissionEntriesAsync(CancellationToken cancel)
        {
            await using var db = Db();
            var dbResult = await db.EFEntries.ToArrayAsync(cancel);

            // entity framework does not know the ulong because it is dumb :(
            return dbResult.Select(a => new StoredAce
                {
                    EntityId = a.EFEntityId,
                    EntryType = (EntryType) a.EntryType,
                    IdentityId = a.IdentityId,
                    LocalOnly = a.LocalOnly,
                    AllowBits = a.AllowBits.ToUInt64(),
                    DenyBits = a.DenyBits.ToUInt64()
                })
                .ToArray();
        }

        [Obsolete("Use async version instead.", true)]
        public IEnumerable<StoredAce> LoadPermissionEntries(IEnumerable<int> entityIds)
        {
            return LoadPermissionEntriesAsync(entityIds, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<IEnumerable<StoredAce>> LoadPermissionEntriesAsync(IEnumerable<int> entityIds, CancellationToken cancel)
        {
            await using var db = Db();
            var dbResult = await db.EFEntries
                .Where(x => entityIds.Contains(x.EFEntityId))
                .ToArrayAsync(cancel);

            // entity framework does not know the ulong because it is dumb :(
            return dbResult.Select(a => new StoredAce
                {
                    EntityId = a.EFEntityId,
                    EntryType = (EntryType) a.EntryType,
                    IdentityId = a.IdentityId,
                    LocalOnly = a.LocalOnly,
                    AllowBits = a.AllowBits.ToUInt64(),
                    DenyBits = a.DenyBits.ToUInt64()
                })
                .ToArray();
        }

        [Obsolete("Use async version instead.", true)]
        public void WritePermissionEntries(IEnumerable<StoredAce> aces)
        {
            WritePermissionEntriesAsync(aces, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task WritePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            var storedAces = aces as StoredAce[] ?? aces.ToArray();
            try
            {
                await using var db = Db();
                await db.WritePermissionEntriesAsync(storedAces, cancel);
            }
            catch (SqlException ex)
            {
                // possible foreign key constraint error
                var message = ex.Message.StartsWith("The INSERT statement conflicted with the FOREIGN KEY constraint")
                    ? "Cannot write permission entries because one of the entities is missing from the database. " +
                        // ReSharper disable once PossibleMultipleEnumeration
                        string.Join(",", storedAces.Select(a => a.EntityId).Distinct().OrderBy(ei => ei))
                    : "Cannot write permission entries because of a database error.";

                throw new SecurityStructureException(message, ex);
            }
        }

        public void RemovePermissionEntries(IEnumerable<StoredAce> aces)
        {
            RemovePermissionEntriesAsync(aces, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task RemovePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            await using var db = Db();
            await db.RemovePermissionEntriesAsync(aces, cancel);
        }

        [Obsolete("Use async version instead.", true)]
        public void RemovePermissionEntriesByEntity(int entityId)
        {
            RemovePermissionEntriesByEntityAsync(entityId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task RemovePermissionEntriesByEntityAsync(int entityId, CancellationToken cancel)
        {
            await using var db = Db();
            await db.RemovePermissionEntriesByEntityAsync(entityId, cancel);
        }

        [Obsolete("Use async version instead.", true)]
        public void DeleteEntitiesAndEntries(int entityId)
        {
            DeleteEntitiesAndEntriesAsync(entityId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task DeleteEntitiesAndEntriesAsync(int entityId, CancellationToken cancel)
        {
            await using var db = Db();
            await db.DeleteEntitiesAndEntriesAsync(entityId, cancel);
        }

        //===================================================================== SecurityActivity

        [Obsolete("Use async version instead.", true)]
        public int GetLastSecurityActivityId(DateTime startedTime)
        {
            return GetLastSecurityActivityIdAsync(startedTime, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<int> GetLastSecurityActivityIdAsync(DateTime startedTime, CancellationToken cancel)
        {
            await using var db = Db();
            var lastMsg = await db.EFMessages.OrderByDescending(e => e.Id).FirstOrDefaultAsync(cancel);
            return lastMsg?.Id ?? 0;
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
            using var db = Db();
            return db.GetUnprocessedActivityIds();
        }
        /// <summary>
        /// Loads a SecurityActivity fragment within the specified limits.
        /// If the count of activities in the id boundary ("from", "to") is bigger
        /// than the given fragment size ("count"), the largest id could not reach.
        /// Activities in the result array are sorted by id.
        /// Value of the IsUnprocessedActivity property of every loaded object
        /// will be the value of the given "executingUnprocessedActivities" parameter.
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
                    var activity = ActivitySerializer.DeserializeActivity(item.Body);
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
        /// will be the value of the given "executingUnprocessedActivities" parameter.
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
                    var activity = ActivitySerializer.DeserializeActivity(item.Body);
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
            using var db = Db();
            var item = db.EFMessages.FirstOrDefault(x => x.Id == id);
            if (item == null)
                return null;

            var activity = ActivitySerializer.DeserializeActivity(item.Body);
            activity.Id = item.Id;
            return activity;
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
            var body = ActivitySerializer.SerializeActivity(activity);
            bodySize = body.Length;
            EntityEntry<EFMessage> result;
            using (var db = Db())
            {
                result = db.EFMessages.Add(new EFMessage
                {
                    ExecutionState = ExecutionState.Wait,
                    SavedBy = _messageSenderManager.InstanceId,
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
            using var db = Db();
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
                        securityActivity.Id, _messageSenderManager.InstanceId, timeoutInSeconds);

                // ReSharper disable once SwitchStatementMissingSomeCases
                switch (result)
                {
                    case ExecutionState.LockedForYou:
                        // enable full executing
                        return new SecurityActivityExecutionLock(securityActivity, this, true);
                    case ExecutionState.Executing:
                    case ExecutionState.Done:
                        // enable partially executing
                        return new SecurityActivityExecutionLock(securityActivity, this, false);
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
            using var db = Db();
            db.RefreshSecurityActivityExecutionLock(securityActivity.Id);
        }
        /// <summary>
        /// Releases the lock and prevents locking that activity again by setting its state to Executed.
        /// </summary>
        public void ReleaseSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            using var db = Db();
            db.ReleaseSecurityActivityExecutionLock(securityActivity.Id);
        }

        //===================================================================== Tools

        private static Task<EFEntity> LoadEFEntityAsync(int entityId, SecurityStorage db, CancellationToken cancel)
        {
            return db.EFEntities.FirstOrDefaultAsync(x => x.Id == entityId, cancel);
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
                // ReSharper disable once LoopCanBeConvertedToQuery
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

        [Obsolete("Use async version instead.", true)]
        public IEnumerable<SecurityGroup> LoadAllGroups()
        {
            return LoadAllGroupsAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public Task<IEnumerable<SecurityGroup>> LoadAllGroupsAsync(CancellationToken cancel)
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
            return Task.FromResult((IEnumerable<SecurityGroup>)groups.Values); //UNDONE:x: async ???
        }

        private static SecurityGroup EnsureGroup(int groupId, Dictionary<int, SecurityGroup> groups)
        {
            if (groups.TryGetValue(groupId, out var group))
                return group;
            group = new SecurityGroup(groupId);
            groups.Add(group.Id, group);
            return group;
        }

        [Obsolete("Use async version instead.", true)]
        public SecurityGroup LoadSecurityGroup(int groupId)
        {
            return LoadSecurityGroupAsync(groupId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task<SecurityGroup> LoadSecurityGroupAsync(int groupId, CancellationToken cancel)
        {
            var group = new SecurityGroup(groupId);
            var groups = new Dictionary<int, SecurityGroup> { { group.Id, group } };
            var rows = 0;
            await using (var db = Db())
            {
                foreach (var membership in await db.EFMemberships.Where(x => x.GroupId == groupId).ToArrayAsync(cancel))
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

        [Obsolete("Use async version instead.", true)]
        public void DeleteIdentityAndRelatedEntries(int identityId)
        {
            DeleteIdentityAndRelatedEntriesAsync(identityId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task DeleteIdentityAndRelatedEntriesAsync(int identityId, CancellationToken cancel)
        {
            await using var db = Db();
            await db.DeleteIdentityAsync(identityId, cancel);
        }

        [Obsolete("Use async version instead.", true)]
        public void DeleteIdentitiesAndRelatedEntries(IEnumerable<int> ids)
        {
            DeleteIdentitiesAndRelatedEntriesAsync(ids, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task DeleteIdentitiesAndRelatedEntriesAsync(IEnumerable<int> ids, CancellationToken cancel)
        {
            await using var db = Db();
            await db.DeleteIdentitiesAsync(ids, cancel);
        }

        [Obsolete("Use async version instead.", true)]
        [SuppressMessage("ReSharper", "ConvertToNullCoalescingCompoundAssignment")]
        public void AddMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            AddMembersAsync(groupId, userMembers, groupMembers, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task AddMembersAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, CancellationToken cancel)
        {
            groupMembers = groupMembers ?? Array.Empty<int>();
            userMembers = userMembers ?? Array.Empty<int>();

            var groupArray = groupMembers as int[] ?? groupMembers.ToArray();
            var userArray = userMembers as int[] ?? userMembers.ToArray();

            var allNewMembers = groupArray.Union(userArray);
            await using var db = Db();
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

            await db.SaveChangesAsync(cancel);
        }

        public void RemoveMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            RemoveMembersAsync(groupId, userMembers, groupMembers, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public async Task RemoveMembersAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, CancellationToken cancel)
        {
            await using var db = Db();
            await db.RemoveMembersAsync(groupId, userMembers ?? Array.Empty<int>(), groupMembers ?? Array.Empty<int>(), cancel);
        }

        //============================================================

        /// <summary>
        /// Returns with information for consistency check: a compound number containing the group's and the member's id.
        /// </summary>
        public IEnumerable<long> GetMembershipForConsistencyCheck()
        {
            using var db = Db();
            return db.EFMemberships.AsEnumerable().Select(m => (Convert.ToInt64(m.GroupId) << 32) + m.MemberId).ToArray();
        }
    }
}
