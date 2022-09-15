using System;
using System.Collections.Generic;
using System.Data;
using Microsoft.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace SenseNet.Security.EFCSecurityStore
{
    internal class SecurityStorage : DbContext
    {
        private readonly EFCSecurityDataProvider _provider;

        public SecurityStorage(EFCSecurityDataProvider provider)
        {
            _provider = provider;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            _provider.ConfigureStorage(optionsBuilder);
            base.OnConfiguring(optionsBuilder);
        }

        /* ------------------------------------ */

        // ReSharper disable once InconsistentNaming
        public DbSet<EFEntity> EFEntities { get; set; }
        // ReSharper disable once InconsistentNaming
        public DbSet<EFEntry> EFEntries { get; set; }
        // ReSharper disable once InconsistentNaming
        public DbSet<EFMembership> EFMemberships { get; set; }
        // ReSharper disable once InconsistentNaming
        public DbSet<EFMessage> EFMessages { get; set; }

        internal DbSet<EfcIntItem> EfcIntSet { get; set; }
        internal DbSet<EfcStringItem> EfcStringSet { get; set; }
        internal DbSet<EfcStoredSecurityEntity> EfcStoredSecurityEntitySet { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<EFEntity>()
                //.HasOptional(e => e.Parent)
                .HasOne(e => e.Parent)
                .WithMany(e => e.Children)
                .IsRequired(false)
                .HasForeignKey(e => e.ParentId)
                .OnDelete(DeleteBehavior.ClientSetNull);

            modelBuilder.Entity<EFEntry>()
                .HasOne(e => e.EFEntity)
                .WithMany(f => f.EFEntries)
                .IsRequired()
                .HasForeignKey(e => e.EFEntityId)
                .OnDelete(DeleteBehavior.ClientSetNull);

            modelBuilder.Entity<EFMembership>().HasKey(a => new { a.GroupId, a.MemberId });

            modelBuilder.Entity<EFEntry>().HasKey(a => new { a.EFEntityId, a.EntryType, a.IdentityId, a.LocalOnly });

            //// ----------------------------------- query types

            //modelBuilder
            //    .Query<EfcIntResult>().ToView("")
            //    .Property(x => x.Value).HasColumnName("Value");

            // -----------------------------------

            base.OnModelCreating(modelBuilder);
        }

        /*========================================================================= Direct SQL queries */

        /// <summary>Only for tests</summary>
        private const string CleanupDatabaseScript = @"
DELETE FROM EFEntries
DELETE FROM EFMemberships
DELETE FROM EFEntities
DELETE FROM EFMessages
";
        /// <summary>Only for re-installation and tests.</summary>
        internal void CleanupDatabase()
        {
            Database.ExecuteSqlRaw(CleanupDatabaseScript);
        }
        internal void ExecuteTestScript(string sql)
        {
            Database.ExecuteSqlRaw(sql);
        }
        internal IEnumerable<T> ExecuteTestScript<T>(string sql)
        {
            if (typeof(T) == typeof(int))
                return (IEnumerable<T>)EfcIntSet.FromSqlRaw(sql).Select(x=>x.Value).AsEnumerable();
            if (typeof(T) == typeof(string))
                return (IEnumerable<T>)EfcStringSet.FromSqlRaw(sql).Select(x => x.Value).AsEnumerable();
            throw new NotSupportedException();
        }

        internal async Task<int> GetEstimatedEntityCountAsync(CancellationToken cancel)
        {
            var result = await EfcIntSet
                .FromSqlRaw("SELECT 1 AS Id, COUNT(1) AS Value FROM EFEntities")
                .SingleAsync(cancel).ConfigureAwait(false);
            return result.Value;
        }

        /// <summary>
        /// Name of the SQL script resource file that contains all the table and constraint creation commands.
        /// </summary>
        private const string ResourceInstallDb = "SenseNet.Security.EFCSecurityStore.Scripts.Install_Schema_4.0.sql";

        internal void InstallDatabase()
        {
            var createDbScript = LoadResourceScript(ResourceInstallDb);

            Database.ExecuteSqlRaw(createDbScript);
        }

        /// <summary>Only for tests</summary>
        private const string CleanupMembershipScript = @"DELETE FROM EFMemberships";
        /// <summary>Only for tests</summary>
        internal void _cleanupMembership()
        {
            Database.ExecuteSqlRaw(CleanupMembershipScript);
        }


        private const string SelectUnprocessedActivityIds = @"DECLARE @lastInserted INT
DECLARE @ident INT
SELECT @lastInserted = MAX(Id) FROM EFMessages
SELECT @ident = CONVERT(int, IDENT_CURRENT('EFMessages'))
SELECT Id, Id AS [Value] FROM [EFMessages] WHERE ExecutionState != 'Done'
UNION ALL
SELECT 0, CASE WHEN @lastInserted IS NULL AND @ident = 1 THEN 0 ELSE @ident END [Value]
--ORDER BY Id
";
        internal async Task<int[]> GetUnprocessedActivityIdsAsync(CancellationToken cancel)
        {
            var dbResult = await EfcIntSet
                .FromSqlRaw(SelectUnprocessedActivityIds)
                .ToArrayAsync(cancel).ConfigureAwait(false);
            var result = dbResult
                .Select(x => x.Value)
                .OrderBy(x => x)
                .ToArray();
            return result;
        }


        private const string LoadStoredSecurityEntityByIdScript = @"
SELECT TOP 1 E.Id, E.OwnerId nullableOwnerId, E.ParentId nullableParentId, E.IsInherited, convert(bit, case when E2.EFEntityId is null then 0 else 1 end) as HasExplicitEntry 
FROM EFEntities E LEFT OUTER JOIN EFEntries E2 ON E2.EFEntityId = E.Id WHERE E.Id = @EntityId";
        internal async Task<StoredSecurityEntity> LoadStoredSecurityEntityByIdAsync(int entityId, CancellationToken cancel)
        {
            var result = await EfcStoredSecurityEntitySet
                // ReSharper disable once FormatStringProblem
                .FromSqlRaw(LoadStoredSecurityEntityByIdScript, new SqlParameter("@EntityId", entityId))
                .Select(x => new StoredSecurityEntity
                {
                    Id = x.Id,
                    IsInherited = x.IsInherited,
                    HasExplicitEntry = x.HasExplicitEntry,
                    nullableParentId = x.nullableParentId,
                    nullableOwnerId = x.nullableOwnerId
                })
                .FirstOrDefaultAsync(cancel).ConfigureAwait(false);
            return result;
        }

        private const string LoadAffectedEntityIdsByEntriesAndBreaksScript = @"SELECT DISTINCT Id AS Value FROM (SELECT DISTINCT EFEntityId Id FROM [EFEntries] UNION ALL SELECT Id FROM [EFEntities] WHERE IsInherited = 0) AS x";
        internal async Task<IEnumerable<int>> LoadAffectedEntityIdsByEntriesAndBreaksAsync(CancellationToken cancel)
        {
            var result = await EfcIntSet
                .FromSqlRaw(LoadAffectedEntityIdsByEntriesAndBreaksScript)
                .Select(x => x.Value)
                .ToArrayAsync(cancel).ConfigureAwait(false);
            return (IEnumerable<int>)result;
        }


        private const string RemovePermissionEntriesScript = @"DELETE FROM EFEntries WHERE EFEntityId = {0} AND EntryType = {1} AND IdentityId = {2} AND LocalOnly = {3}";
        internal async Task RemovePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            var storedAces = aces as StoredAce[] ?? aces.ToArray();
            var count = storedAces.Length;
            if (count == 0)
                return;

            var sb = new StringBuilder();

            if (count > 1)
            {
                sb.AppendLine("SET XACT_ABORT ON;");
                sb.AppendLine("BEGIN TRANSACTION");
                sb.AppendLine();
            }

            foreach (var ace in storedAces)
                sb.AppendFormat(RemovePermissionEntriesScript, ace.EntityId, (int)ace.EntryType, ace.IdentityId, ace.LocalOnly ? 1 : 0).AppendLine();

            if (count > 1)
            {
                sb.AppendLine();
                sb.AppendLine("COMMIT TRANSACTION");
            }

            await Database.ExecuteSqlRawAsync(sb.ToString(), cancel).ConfigureAwait(false);
        }

        private const string InsertPermissionEntriesScript = @"INSERT INTO EFEntries SELECT {0}, {1}, {2}, {3}, {4}, {5}";
        internal async Task WritePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel)
        {
            var storedAces = aces as StoredAce[] ?? aces.ToArray();
            var count = storedAces.Length;
            if (count == 0)
                return;

            var sb = new StringBuilder();

            sb.AppendLine("SET XACT_ABORT ON;");
            sb.AppendLine("BEGIN TRANSACTION");
            sb.AppendLine();

            foreach (var ace in storedAces)
                sb.AppendFormat(RemovePermissionEntriesScript, ace.EntityId, (int)ace.EntryType, ace.IdentityId, ace.LocalOnly ? 1 : 0).AppendLine();
            sb.AppendLine();
            foreach (var ace in storedAces)
                sb.AppendFormat(InsertPermissionEntriesScript, ace.EntityId, (int)ace.EntryType, ace.IdentityId, ace.LocalOnly ? 1 : 0
                    , ace.AllowBits.ToInt64()
                    , ace.DenyBits.ToInt64()).AppendLine();

            sb.AppendLine();
            sb.AppendLine("COMMIT TRANSACTION");

            await Database.ExecuteSqlRawAsync(sb.ToString(), cancel).ConfigureAwait(false);
        }


        private const string RemovePermissionEntriesByEntityScript = @"DELETE FROM EFEntries WHERE EFEntityId = @EntityId";
        internal Task RemovePermissionEntriesByEntityAsync(int entityId, CancellationToken cancel)
        {
            return Database.ExecuteSqlRawAsync(RemovePermissionEntriesByEntityScript,
                new[] {new SqlParameter("@EntityId", entityId)}, cancel);
        }

        private const string DeleteEntitiesAndEntriesScript = @"DECLARE @EntityIdTable TABLE (EntityId int)
;WITH EntityCTE as (
SELECT Id, ParentId
FROM EFEntities
WHERE Id = @EntityId
UNION ALL
SELECT E.Id, E.ParentId
FROM EFEntities E
INNER JOIN EntityCTE ON E.ParentId = EntityCTE.Id
)
INSERT INTO @EntityIdTable
SELECT Id FROM EntityCTE

DELETE E1 FROM EFEntries E1 INNER JOIN @EntityIdTable E2 ON E2.EntityId = E1.EFEntityId
DELETE E1 FROM EFEntities E1 INNER JOIN @EntityIdTable E2 ON E2.EntityId = E1.Id";

        internal Task DeleteEntitiesAndEntriesAsync(int entityId, CancellationToken cancel)
        {
            // This script collects all entity ids in a subtree (including the provided root),
            // deletes all security entries related to them, then deletes all entities.
            return Database.ExecuteSqlRawAsync(DeleteEntitiesAndEntriesScript,
                new[] { new SqlParameter("@EntityId", entityId) }, cancel);
        }

        private const string CleanupSecurityActivitiesScript = @"DELETE FROM EFMessages WHERE SavedAt < DATEADD(minute, -@TimeLimit, GETUTCDATE()) AND ExecutionState = 'Done'";
        internal Task CleanupSecurityActivitiesAsync(int timeLimitInMinutes, CancellationToken cancel)
        {
            return Database.ExecuteSqlRawAsync(CleanupSecurityActivitiesScript, 
                new[]{new SqlParameter("@TimeLimit", timeLimitInMinutes)}, cancel);
        }

        // ReSharper disable once ConvertToConstant.Local
        private static readonly string AcquireSecurityActivityExecutionLockScript = @"UPDATE EFMessages
	SET ExecutionState = '" + ExecutionState.Executing + @"', LockedBy = @LockedBy, LockedAt = GETUTCDATE()
	WHERE Id = @ActivityId AND ((ExecutionState = '" + ExecutionState.Wait + @"') OR (ExecutionState = '" + ExecutionState.Executing + @"' AND LockedAt < DATEADD(second, -@TimeLimit, GETUTCDATE())))
IF (@@rowcount > 0)
	SELECT 1 as Id, '" + ExecutionState.LockedForYou + @"' AS Value
ELSE
	SELECT Id, ExecutionState AS Value FROM EFMessages WHERE Id = @ActivityId
";
        public async Task<string> AcquireSecurityActivityExecutionLockAsync(int securityActivityId, string lockedBy, int timeoutInSeconds,
            CancellationToken cancel)
        {
            var dbResult = await EfcStringSet
                .FromSqlRaw(AcquireSecurityActivityExecutionLockScript,
                        new SqlParameter("@ActivityId", securityActivityId),
                        new SqlParameter("@LockedBy", lockedBy ?? ""),
                        new SqlParameter("@TimeLimit", timeoutInSeconds))
                .ToArrayAsync(cancel).ConfigureAwait(false);

            var result = string.Empty;

            // We use foreach here instead of Single or First, because Entity Framework
            // generates an outer SELECT for those methods that result in an incorrect
            // SQL syntax.
            foreach (var item in dbResult)
            {
                // read the first and only item and return immediately
                result = item.Value;
                break;
            }

            return result;
        }

        // ReSharper disable once ConvertToConstant.Local
        private static readonly string RefreshSecurityActivityExecutionLockScript = @"UPDATE EFMessages SET LockedAt = GETUTCDATE() WHERE Id = @ActivityId";
        public Task RefreshSecurityActivityExecutionLockAsync(int securityActivityId, CancellationToken cancel)
        {
            return Database.ExecuteSqlRawAsync(RefreshSecurityActivityExecutionLockScript,
                new[] {new SqlParameter("@ActivityId", securityActivityId)}, cancel);
        }

        // ReSharper disable once ConvertToConstant.Local
        private static readonly string ReleaseSecurityActivityExecutionLockScript = @"UPDATE EFMessages SET ExecutionState = '" + ExecutionState.Done + @"' WHERE Id = @ActivityId";
        public Task ReleaseSecurityActivityExecutionLockAsync(int securityActivityId, CancellationToken cancel)
        {
            return Database.ExecuteSqlRawAsync(ReleaseSecurityActivityExecutionLockScript,
                new[] {new SqlParameter("@ActivityId", securityActivityId)}, cancel);
        }

        private const string DeleteIdentityScript = @"DELETE FROM EFMemberships WHERE GroupId = @IdentityId OR MemberId = @IdentityId
DELETE FROM EFEntries WHERE IdentityId = @IdentityId";
        internal Task DeleteIdentityAsync(int identityId, CancellationToken cancel)
        {
            return Database.ExecuteSqlRawAsync(DeleteIdentityScript,
                new[] {new SqlParameter("@IdentityId", identityId)}, cancel);
        }

        private const string DeleteIdentitiesScript = @"
SET XACT_ABORT ON;
BEGIN TRANSACTION

-- convert xml to a table containing the ids
DECLARE @Identities TABLE (Id int)
INSERT INTO @Identities
SELECT Id.value('.', 'int') FROM @IdentityList.nodes('/Ids/Id') as Identifiers(Id);

-- Delete all ACEs related to the identities
DELETE E1 FROM EFEntries E1 INNER JOIN @Identities I1 ON E1.IdentityId = I1.Id
-- Delete all memberships: the id can be a group or a member too
DELETE M1 FROM EFMemberships M1 INNER JOIN @Identities I1 ON M1.GroupId = I1.Id OR M1.MemberId = I1.Id

COMMIT TRANSACTION";
        internal async Task DeleteIdentitiesAsync(IEnumerable<int> ids, CancellationToken cancel)
        {
            // construct an xml from the given id list for the sql command to make an id list on the SQL Server side
            var param = new SqlParameter("@IdentityList", SqlDbType.Xml)
            {
                Value = string.Format(IdListXmlTemplate, string.Join(string.Empty, ids.Select(identityId => string.Format(IdListItemXmlTemplate, identityId))))
            };

            await Database.ExecuteSqlRawAsync(DeleteIdentitiesScript, new[] {param}, cancel).ConfigureAwait(false);
        }

        private const string RemoveMembersScript = @"DELETE FROM EFMemberships WHERE GroupId = @GroupId AND MemberId IN ({0})";
        internal async Task RemoveMembersAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers,
            CancellationToken cancel)
        {
            var sql = string.Format(RemoveMembersScript, string.Join(", ", groupMembers.Union(userMembers)));
            await Database.ExecuteSqlRawAsync(sql, new[] {new SqlParameter("@GroupId", groupId)}, cancel).ConfigureAwait(false);
        }


        private const string IdListXmlTemplate = @"<Ids>{0}</Ids>";
        private const string IdListItemXmlTemplate = @"<Id>{0}</Id>";

        private static string LoadResourceScript(string resourceName)
        {
            var assembly = Assembly.GetExecutingAssembly();

            using var scriptStream = assembly.GetManifestResourceStream(resourceName);
            if (scriptStream == null)
                throw new ApplicationException("Script resource not found in the assembly: " + resourceName);

            using var reader = new StreamReader(scriptStream);
            return reader.ReadToEnd();
        }
    }
}
