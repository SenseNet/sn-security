using System;
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
        [Obsolete("Use the constructor with IOptions and dependency injection instead.", true)]
        //UNDONE:DI Use the constructor with IOptions and dependency injection instead.
        public EFCSecurityDataProvider(IMessageSenderManager messageSenderManager) : this(messageSenderManager, 0, null)
        {
        }
        /// <summary>Initializes a new instance of the EFCSecurityDataProvider class.</summary>
        [Obsolete("Use the constructor with IOptions and dependency injection instead.", true)]
        //UNDONE:DI Use the constructor with IOptions and dependency injection instead.
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

        [Obsolete("Use async version instead.")]
        public int GetEstimatedEntityCount()
        {
            return GetEstimatedEntityCountAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<int> GetEstimatedEntityCountAsync(CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                return await db.GetEstimatedEntityCountAsync(cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public IEnumerable<StoredSecurityEntity> LoadSecurityEntities()
        {
            return LoadSecurityEntitiesAsync(CancellationToken.None).GetAwaiter().GetResult();
        }

        public async Task<IEnumerable<StoredSecurityEntity>> LoadSecurityEntitiesAsync(CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                return await db.EFEntities.Select(x => new StoredSecurityEntity
                {
                    Id = x.Id,
                    nullableOwnerId = x.OwnerId,
                    nullableParentId = x.ParentId,
                    IsInherited = x.IsInherited
                }).ToArrayAsync(cancel).ConfigureAwait(false);
            }
        }

        [Obsolete("Use async version instead.")]
        public IEnumerable<int> LoadAffectedEntityIdsByEntriesAndBreaks()
        {
            return LoadAffectedEntityIdsByEntriesAndBreaksAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<IEnumerable<int>> LoadAffectedEntityIdsByEntriesAndBreaksAsync(CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                return await db.LoadAffectedEntityIdsByEntriesAndBreaksAsync(cancel).ConfigureAwait(false);
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

        [Obsolete("Use async version instead.")]
        public StoredSecurityEntity LoadStoredSecurityEntity(int entityId)
        {
            return LoadStoredSecurityEntityAsync(entityId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<StoredSecurityEntity> LoadStoredSecurityEntityAsync(int entityId, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                return await db.LoadStoredSecurityEntityByIdAsync(entityId, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public void InsertSecurityEntity(StoredSecurityEntity entity)
        {
            InsertSecurityEntityAsync(entity, CancellationToken.None).GetAwaiter().GetResult();
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
                await db.SaveChangesAsync(cancel).ConfigureAwait(false);
            }
            catch (DbUpdateException)
            {
                // entity already exists, that's ok
            }
        }

        [Obsolete("Use async version instead.")]
        public void UpdateSecurityEntity(StoredSecurityEntity entity)
        {
            UpdateSecurityEntityAsync(entity, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task UpdateSecurityEntityAsync(StoredSecurityEntity entity, CancellationToken cancel)
        {
            var exceptions = new List<Exception>();

            for (var retry = 3; retry > 0; retry--)
            {
                try
                {
                    var db = Db();
                    await using (db.ConfigureAwait(false))
                    {
                        var oldEntity = await LoadEFEntityAsync(entity.Id, db, cancel).ConfigureAwait(false);
                        if (oldEntity == null)
                            throw new EntityNotFoundException("Cannot update entity because it does not exist: " + entity.Id);

                        oldEntity.OwnerId = entity.nullableOwnerId;
                        oldEntity.ParentId = entity.nullableParentId;
                        oldEntity.IsInherited = entity.IsInherited;

                        await db.SaveChangesAsync(cancel).ConfigureAwait(false);
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

            // the loop was finished after several attempts
            if (exceptions.Count > 0)
                throw new SecurityStructureException(
                    "Cannot update entity because of concurrency: " + entity.Id, new AggregateException(exceptions));
        }

        [Obsolete("Use async version instead.")]
        public void DeleteSecurityEntity(int entityId)
        {
            DeleteSecurityEntityAsync(entityId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task DeleteSecurityEntityAsync(int entityId, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var oldEntity = db.EFEntities.FirstOrDefault(x => x.Id == entityId);
                if (oldEntity == null)
                    return;
                db.EFEntities.Remove(oldEntity);
                try
                {
                    await db.SaveChangesAsync(cancel).ConfigureAwait(false);
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

        [Obsolete("Use async version instead.")]
        public void MoveSecurityEntity(int sourceId, int targetId) // always called with SetSecurityHolder method
        {
            MoveSecurityEntityAsync(sourceId, targetId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task MoveSecurityEntityAsync(int sourceId, int targetId, CancellationToken cancel) // always called with SetSecurityHolder method
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var source = await LoadEFEntityAsync(sourceId, db, cancel).ConfigureAwait(false);
                if (source == null)
                    throw new EntityNotFoundException(
                        "Cannot execute the move operation because source does not exist: " + sourceId);
                var target = await LoadEFEntityAsync(targetId, db, cancel).ConfigureAwait(false);
                if (target == null)
                    throw new EntityNotFoundException(
                        "Cannot execute the move operation because target does not exist: " + targetId);

                source.ParentId = target.Id;

                await db.SaveChangesAsync(cancel).ConfigureAwait(false);
            }
        }

        [Obsolete("Use async version instead.")]
        public IEnumerable<StoredAce> LoadAllPermissionEntries()
        {
            return LoadAllPermissionEntriesAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<IEnumerable<StoredAce>> LoadAllPermissionEntriesAsync(CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var dbResult = await db.EFEntries.ToArrayAsync(cancel).ConfigureAwait(false);

                // entity framework does not know the ulong because it is dumb :(
                return dbResult.Select(a => new StoredAce
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

        [Obsolete("Use async version instead.")]
        public IEnumerable<StoredAce> LoadPermissionEntries(IEnumerable<int> entityIds)
        {
            return LoadPermissionEntriesAsync(entityIds, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<IEnumerable<StoredAce>> LoadPermissionEntriesAsync(IEnumerable<int> entityIds, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var dbResult = await db.EFEntries
                    .Where(x => entityIds.Contains(x.EFEntityId))
                    .ToArrayAsync(cancel).ConfigureAwait(false);

                // entity framework does not know the ulong because it is dumb :(
                return dbResult.Select(a => new StoredAce
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

        [Obsolete("Use async version instead.")]
        public void WritePermissionEntries(IEnumerable<StoredAce> aces)
        {
            WritePermissionEntriesAsync(aces, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task WritePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            var storedAces = aces as StoredAce[] ?? aces.ToArray();
            try
            {
                var db = Db();
                await using (db.ConfigureAwait(false))
                    await db.WritePermissionEntriesAsync(storedAces, cancel).ConfigureAwait(false);
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

        [Obsolete("Use async version instead.")]
        public void RemovePermissionEntries(IEnumerable<StoredAce> aces)
        {
            RemovePermissionEntriesAsync(aces, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task RemovePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                await db.RemovePermissionEntriesAsync(aces, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public void RemovePermissionEntriesByEntity(int entityId)
        {
            RemovePermissionEntriesByEntityAsync(entityId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task RemovePermissionEntriesByEntityAsync(int entityId, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                await db.RemovePermissionEntriesByEntityAsync(entityId, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public void DeleteEntitiesAndEntries(int entityId)
        {
            DeleteEntitiesAndEntriesAsync(entityId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task DeleteEntitiesAndEntriesAsync(int entityId, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                await db.DeleteEntitiesAndEntriesAsync(entityId, cancel).ConfigureAwait(false);
        }

        //===================================================================== SecurityActivity

        [Obsolete("Use async version instead.")]
        public int GetLastSecurityActivityId(DateTime startedTime)
        {
            return GetLastSecurityActivityIdAsync(startedTime, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<int> GetLastSecurityActivityIdAsync(DateTime startedTime, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var lastMsg = await db.EFMessages.OrderByDescending(e => e.Id).FirstOrDefaultAsync(cancel).ConfigureAwait(false);
                return lastMsg?.Id ?? 0;
            }
        }

        [Obsolete("Use async version instead.")]
        public int[] GetUnprocessedActivityIds()
        {
            return GetUnprocessedActivityIdsAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<int[]> GetUnprocessedActivityIdsAsync(CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                return await db.GetUnprocessedActivityIdsAsync(cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public SecurityActivity[] LoadSecurityActivities(int from, int to, int count, bool executingUnprocessedActivities)
        {
            return LoadSecurityActivitiesAsync(from, to, count, executingUnprocessedActivities, CancellationToken.None)
                .GetAwaiter().GetResult();
        }
        public async Task<SecurityActivity[]> LoadSecurityActivitiesAsync(int from, int to, int count, bool executingUnprocessedActivities,
            CancellationToken cancel)
        {
            var result = new List<SecurityActivity>();
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var items = await db.EFMessages
                    .Where(x => x.Id >= from && x.Id <= to)
                    .OrderBy(x => x.Id)
                    .Take(count)
                    .ToArrayAsync(cancel).ConfigureAwait(false);

                foreach (var item in items)
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

        [Obsolete("Use async version instead.")]
        public SecurityActivity[] LoadSecurityActivities(int[] gaps, bool executingUnprocessedActivities)
        {
            return LoadSecurityActivitiesAsync(gaps, executingUnprocessedActivities, CancellationToken.None)
                .GetAwaiter().GetResult();
        }
        public async Task<SecurityActivity[]> LoadSecurityActivitiesAsync(int[] gaps, bool executingUnprocessedActivities, CancellationToken cancel)
        {
            var result = new List<SecurityActivity>();
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var items = await db.EFMessages
                    .Where(x => gaps.Contains(x.Id))
                    .OrderBy(x => x.Id)
                    .ToArrayAsync(cancel).ConfigureAwait(false);

                foreach (var item in items)
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

        [Obsolete("Use async version instead.")]
        public SecurityActivity LoadSecurityActivity(int id)
        {
            return LoadSecurityActivityAsync(id, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<SecurityActivity> LoadSecurityActivityAsync(int id, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var item = await db.EFMessages.FirstOrDefaultAsync(x => x.Id == id, cancel).ConfigureAwait(false);
                if (item == null)
                    return null;

                var activity = ActivitySerializer.DeserializeActivity(item.Body);
                activity.Id = item.Id;
                return activity;
            }
        }

        [Obsolete("Use async version instead.")]
        public int SaveSecurityActivity(SecurityActivity activity, out int bodySize)
        {
            var result = SaveSecurityActivityAsync(activity, CancellationToken.None).GetAwaiter().GetResult();
            bodySize = result.BodySize;
            return result.ActivityId;
        }
        public async Task<SaveSecurityActivityResult> SaveSecurityActivityAsync(SecurityActivity activity, CancellationToken cancel)
        {
            var body = ActivitySerializer.SerializeActivity(activity);
            EntityEntry<EFMessage> result;
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                result = db.EFMessages.Add(new EFMessage
                {
                    ExecutionState = ExecutionState.Wait,
                    SavedBy = _messageSenderManager.InstanceId,
                    SavedAt = DateTime.UtcNow,
                    Body = body
                });
                await db.SaveChangesAsync(cancel).ConfigureAwait(false);
            }
            return new SaveSecurityActivityResult {ActivityId = result.Entity.Id, BodySize = body.Length};
        }


        [Obsolete("Use async version instead.")]
        public void CleanupSecurityActivities(int timeLimitInMinutes)
        {
            CleanupSecurityActivitiesAsync(timeLimitInMinutes, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task CleanupSecurityActivitiesAsync(int timeLimitInMinutes, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                await db.CleanupSecurityActivitiesAsync(timeLimitInMinutes, cancel).ConfigureAwait(false);
        }

        /// <summary>
        /// Ensures an exclusive (only one) object for the activity. Returns the new lock object or null.
        /// </summary>
        [Obsolete("Use async version instead.")]
        public SecurityActivityExecutionLock AcquireSecurityActivityExecutionLock(
            SecurityActivity securityActivity, int timeoutInSeconds)
        {
            return AcquireSecurityActivityExecutionLockAsync(securityActivity, timeoutInSeconds, CancellationToken.None)
                .GetAwaiter().GetResult();
        }
        public async Task<SecurityActivityExecutionLock> AcquireSecurityActivityExecutionLockAsync(
            SecurityActivity securityActivity, int timeoutInSeconds, CancellationToken cancel)
        {
            var maxTime = timeoutInSeconds == int.MaxValue
                ? DateTime.MaxValue
                : DateTime.UtcNow.AddSeconds(timeoutInSeconds);
            while (DateTime.UtcNow < maxTime)
            {
                string result;
                var db = Db();
                await using (db.ConfigureAwait(false))
                    result = await db.AcquireSecurityActivityExecutionLockAsync(
                        securityActivity.Id, _messageSenderManager.InstanceId, timeoutInSeconds, cancel).ConfigureAwait(false);

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
        [Obsolete("Use async version instead.")]
        public void RefreshSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            RefreshSecurityActivityExecutionLockAsync(securityActivity, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task RefreshSecurityActivityExecutionLockAsync(SecurityActivity securityActivity, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                await db.RefreshSecurityActivityExecutionLockAsync(securityActivity.Id, cancel).ConfigureAwait(false);
        }

        /// <summary>
        /// Releases the lock and prevents locking that activity again by setting its state to Executed.
        /// </summary>
        [Obsolete("Use async version instead.")]
        public void ReleaseSecurityActivityExecutionLock(SecurityActivity securityActivity)
        {
            ReleaseSecurityActivityExecutionLockAsync(securityActivity, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task ReleaseSecurityActivityExecutionLockAsync(SecurityActivity securityActivity, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                await db.ReleaseSecurityActivityExecutionLockAsync(securityActivity.Id, cancel).ConfigureAwait(false);
        }

        //===================================================================== Tools

        private static Task<EFEntity> LoadEFEntityAsync(int entityId, SecurityStorage db, CancellationToken cancel)
        {
            return db.EFEntities.FirstOrDefaultAsync(x => x.Id == entityId, cancel);
        }

        /* ===================================================================== */

        [Obsolete("Use async version instead.")]
        public void QueryGroupRelatedEntities(
            int groupId, out IEnumerable<int> entityIds, out IEnumerable<int> exclusiveEntityIds)
        {
            var result = QueryGroupRelatedEntitiesAsync(groupId, CancellationToken.None).GetAwaiter().GetResult();
            entityIds = result.EntityIds;
            exclusiveEntityIds = result.ExclusiveEntityIds;
        }
        public async Task<GroupRelatedEntitiesQueryResult> QueryGroupRelatedEntitiesAsync(int groupId, CancellationToken cancel)
        {
            var exclusiveEntityIds = new List<int>();
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var entityIds = await db.EFEntries
                    .Where(x => x.IdentityId == groupId)
                    .Select(x => x.EFEntityId).Distinct()
                    .ToArrayAsync(cancel).ConfigureAwait(false);

                foreach (var relatedEntityId in entityIds)
                {
                    var aces = db.EFEntries.Where(x => x.EFEntityId == relatedEntityId).ToArray();
                    var groupRelatedCount = aces.Count(x => x.IdentityId == groupId);
                    if (aces.Length == groupRelatedCount)
                        exclusiveEntityIds.Add(relatedEntityId);
                }

                return new GroupRelatedEntitiesQueryResult
                {
                    EntityIds = entityIds,
                    ExclusiveEntityIds = exclusiveEntityIds
                };
            }
        }


        /******************************************* membership storage */

        [Obsolete("Use async version instead.")]
        public IEnumerable<SecurityGroup> LoadAllGroups()
        {
            return LoadAllGroupsAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<IEnumerable<SecurityGroup>> LoadAllGroupsAsync(CancellationToken cancel)
        {

            var groups = new Dictionary<int, SecurityGroup>();
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                await db.EFMemberships.ForEachAsync(membership =>
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
                }, cancel).ConfigureAwait(false);
            }
            return groups.Values;
        }

        private static SecurityGroup EnsureGroup(int groupId, Dictionary<int, SecurityGroup> groups)
        {
            if (groups.TryGetValue(groupId, out var group))
                return group;
            group = new SecurityGroup(groupId);
            groups.Add(group.Id, group);
            return group;
        }

        [Obsolete("Use async version instead.")]
        public SecurityGroup LoadSecurityGroup(int groupId)
        {
            return LoadSecurityGroupAsync(groupId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<SecurityGroup> LoadSecurityGroupAsync(int groupId, CancellationToken cancel)
        {
            var group = new SecurityGroup(groupId);
            var groups = new Dictionary<int, SecurityGroup> { { group.Id, group } };
            var rows = 0;
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                foreach (var membership in await db.EFMemberships.Where(x => x.GroupId == groupId).ToArrayAsync(cancel).ConfigureAwait(false))
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

        [Obsolete("Use async version instead.")]
        public void DeleteIdentityAndRelatedEntries(int identityId)
        {
            DeleteIdentityAndRelatedEntriesAsync(identityId, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task DeleteIdentityAndRelatedEntriesAsync(int identityId, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                await db.DeleteIdentityAsync(identityId, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        public void DeleteIdentitiesAndRelatedEntries(IEnumerable<int> ids)
        {
            DeleteIdentitiesAndRelatedEntriesAsync(ids, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task DeleteIdentitiesAndRelatedEntriesAsync(IEnumerable<int> ids, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                await db.DeleteIdentitiesAsync(ids, cancel).ConfigureAwait(false);
        }

        [Obsolete("Use async version instead.")]
        [SuppressMessage("ReSharper", "ConvertToNullCoalescingCompoundAssignment")]
        public void AddMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            AddMembersAsync(groupId, userMembers, groupMembers, CancellationToken.None).GetAwaiter().GetResult();
        }

        public async Task AddMembersAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers,
            CancellationToken cancel)
        {
            groupMembers = groupMembers ?? Array.Empty<int>();
            userMembers = userMembers ?? Array.Empty<int>();

            var groupArray = groupMembers as int[] ?? groupMembers.ToArray();
            var userArray = userMembers as int[] ?? userMembers.ToArray();

            var allNewMembers = groupArray.Union(userArray);
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var origMemberIds = db.EFMemberships
                    .Where(m => m.GroupId == groupId && allNewMembers.Contains(m.MemberId))
                    .Select(m => m.MemberId)
                    .ToArray();
                var newGroupIds = groupArray.Except(origMemberIds).ToArray();
                var newUserIds = userArray.Except(origMemberIds).ToArray();
                var newGroups = newGroupIds.Select(g => new EFMembership
                    {GroupId = groupId, MemberId = g, IsUser = false});
                var newUsers = newUserIds.Select(g => new EFMembership
                    {GroupId = groupId, MemberId = g, IsUser = true});

                db.EFMemberships.AddRange(newGroups);
                db.EFMemberships.AddRange(newUsers);

                await db.SaveChangesAsync(cancel).ConfigureAwait(false);
            }
        }

        [Obsolete("Use async version instead.")]
        public void RemoveMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            RemoveMembersAsync(groupId, userMembers, groupMembers, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task RemoveMembersAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
                await db.RemoveMembersAsync(groupId, userMembers ?? Array.Empty<int>(), groupMembers ?? Array.Empty<int>(), cancel).ConfigureAwait(false);
        }

        //============================================================

        /// <summary>
        /// Returns with information for consistency check: a compound number containing the group's and the member's id.
        /// </summary>
        [Obsolete("Use async version instead.")]
        public IEnumerable<long> GetMembershipForConsistencyCheck()
        {
            return GetMembershipForConsistencyCheckAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task<IEnumerable<long>> GetMembershipForConsistencyCheckAsync(CancellationToken cancel)
        {
            var db = Db();
            await using (db.ConfigureAwait(false))
            {
                var dbResult = await db.EFMemberships.ToArrayAsync(cancel).ConfigureAwait(false);
                return dbResult.Select(m => (Convert.ToInt64(m.GroupId) << 32) + m.MemberId)
                    .ToArray();
            }
        }
    }
}
