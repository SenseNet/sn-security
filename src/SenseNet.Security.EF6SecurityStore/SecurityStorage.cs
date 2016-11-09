using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data;
using System.Data.Entity;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace SenseNet.Security.EF6SecurityStore
{
    internal class SecurityStorage : DbContext
    {
        public SecurityStorage(int commandTimeout, string connection) : base(connection)
        {
            Initialize(commandTimeout);
        }

        public SecurityStorage(int commandTimeout)
        {
            Initialize(commandTimeout);
        }

        private void Initialize(int commandTimeout)
        {
            // necessary for switching OFF automatic database migration
            Database.SetInitializer<SecurityStorage>(null);
            this.Database.CommandTimeout = commandTimeout;
        }

        public DbSet<EFEntity> EFEntities { get; set; }
        public DbSet<EFEntry> EFEntries { get; set; }
        public DbSet<EFMembership> EFMemberships { get; set; }
        public DbSet<EFMessage> EFMessages { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Entity<EFEntity>()
                .Property(e => e.Id)
                .HasDatabaseGeneratedOption(DatabaseGeneratedOption.None);

            modelBuilder.Entity<EFEntity>()
                .HasOptional(e => e.Parent)
                .WithMany(e => e.Children)
                .HasForeignKey(e => e.ParentId).WillCascadeOnDelete(false);

            modelBuilder.Entity<EFEntry>()
                .HasRequired(e => e.EFEntity)
                .WithMany(f => f.EFEntries)
                .HasForeignKey(e => e.EFEntityId).WillCascadeOnDelete(false);

            modelBuilder.Entity<EFMembership>().HasKey(a => new { a.GroupId, a.MemberId });

            modelBuilder.Entity<EFEntry>().HasKey(a => new { a.EFEntityId, a.IdentityId, a.LocalOnly });

            base.OnModelCreating(modelBuilder);
        }

        /*========================================================================= Direct SQL queries */

        /// <summary>Only for tests</summary>
        private const string CLEANUPDATABASESCRIPT = @"
DELETE FROM EFEntries
DELETE FROM EFMemberships
DELETE FROM EFEntities
DELETE FROM EFMessages
";
        /// <summary>Only for re-istallation and tests.</summary>
        internal void CleanupDatabase()
        {
            this.Database.ExecuteSqlCommand(CLEANUPDATABASESCRIPT);
        }
        internal void ExecuteTestScript(string sql)
        {
            this.Database.ExecuteSqlCommand(sql);
        }

        internal int GetEstimatedEntityCount()
        {
            return this.Database.SqlQuery<int>("SELECT COUNT(1) FROM EFEntities").Single();
        }

        internal IEnumerable<T> ExecuteTestScript<T>(string sql)
        {
            return this.Database.SqlQuery<T>(sql).ToArray();
        }

        /// <summary>
        /// Name of the SQL script resource file that contains all the table and constraint creation commands.
        /// </summary>
        private const string RESOURCE_INSTALLDB = "SenseNet.Security.EF6SecurityStore.Scripts.Install_Schema_2.1.sql";

        internal void InstallDatabase()
        {
            var createDbScript = LoadResourceScript(RESOURCE_INSTALLDB);

            this.Database.ExecuteSqlCommand(createDbScript);
        }

        /// <summary>Only for tests</summary>
        private const string CLEANUPMEMBERSHIPSCRIPT = @"DELETE FROM EFMemberships";
        /// <summary>Only for tests</summary>
        internal void _cleanupMembership()
        {
            this.Database.ExecuteSqlCommand(CLEANUPMEMBERSHIPSCRIPT);
        }


        private const string SelectUnprocessedActivityIds = @"SELECT Id FROM [EFMessages] WHERE ExecutionState != 'Done'
UNION ALL
SELECT CONVERT(int, IDENT_CURRENT('EFMessages'))
ORDER BY Id
";
        internal int[] GetUnprocessedActivityIds()
        {
            var x = this.Database.SqlQuery<int>(SelectUnprocessedActivityIds).ToArray();
            return x;
        }


        private const string LoadStoredSecurityEntityById_Script = @"
SELECT TOP 1 E.Id, E.OwnerId nullableOwnerId, E.ParentId nullableParentId, E.IsInherited, convert(bit, case when E2.EFEntityId is null then 0 else 1 end) as HasExplicitEntry 
FROM EFEntities E LEFT OUTER JOIN EFEntries E2 ON E2.EFEntityId = E.Id WHERE E.Id = @EntityId";
        internal StoredSecurityEntity LoadStoredSecurityEntityById(int entityId)
        {
            var x = this.Database.SqlQuery<StoredSecurityEntity>(LoadStoredSecurityEntityById_Script
                , new SqlParameter("@EntityId", entityId)).FirstOrDefault();
            return x;
        }


        private const string LOADAFFECTEDENTITYIDSBYENTRIESANDBREAKSSCRIPT = @"SELECT DISTINCT Id FROM (SELECT DISTINCT EFEntityId Id FROM [EFEntries] UNION ALL SELECT Id FROM [EFEntities] WHERE IsInherited = 0) AS x";
        internal IEnumerable<int> LoadAffectedEntityIdsByEntriesAndBreaks()
        {
            var x = this.Database.SqlQuery<int>(LOADAFFECTEDENTITYIDSBYENTRIESANDBREAKSSCRIPT).ToArray();
            return x;
        }


        private const string REMOVEPERMISSIONENTRIESSCRIPT = @"DELETE FROM EFEntries WHERE EFEntityId = {0} AND IdentityId = {1} AND LocalOnly = {2}";
        internal void RemovePermissionEntries(IEnumerable<StoredAce> aces)
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
                sb.AppendFormat(REMOVEPERMISSIONENTRIESSCRIPT, ace.EntityId, ace.IdentityId, ace.LocalOnly ? 1 : 0).AppendLine();

            if (count > 1)
            {
                sb.AppendLine();
                sb.AppendLine("COMMIT TRANSACTION");
            }

            this.Database.ExecuteSqlCommand(sb.ToString());
        }

        private const string INSERTPERMISSIONENTRIESSCRIPT = @"INSERT INTO EFEntries SELECT {0}, {1}, {2}, {3}, {4}";
        internal void WritePermissionEntries(IEnumerable<StoredAce> aces)
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
                sb.AppendFormat(REMOVEPERMISSIONENTRIESSCRIPT, ace.EntityId, ace.IdentityId, ace.LocalOnly ? 1 : 0).AppendLine();
            sb.AppendLine();
            foreach (var ace in storedAces)
                sb.AppendFormat(INSERTPERMISSIONENTRIESSCRIPT, ace.EntityId, ace.IdentityId, ace.LocalOnly ? 1 : 0
                    , ace.AllowBits.ToInt64()
                    , ace.DenyBits.ToInt64()).AppendLine();

            sb.AppendLine();
            sb.AppendLine("COMMIT TRANSACTION");

            this.Database.ExecuteSqlCommand(sb.ToString());
        }


        private const string RemovePermissionEntriesByEntity_Script = @"DELETE FROM EFEntries WHERE EFEntityId = @EntityId";
        internal void RemovePermissionEntriesByEntity(int entityId)
        {
            this.Database.ExecuteSqlCommand(RemovePermissionEntriesByEntity_Script, new SqlParameter("@EntityId", entityId));
        }

        private const string DELETE_ENTITIESANDENTRIESSCRIPT = @"DECLARE @EntityIdTable TABLE (EntityId int)
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

        internal void DeleteEntitiesAndEntries(int entityId)
        {
            // This script collects all entity ids in a subtree (including the provided root),
            // deletes all security entries related to them, then deletes all entities.
            this.Database.ExecuteSqlCommand(DELETE_ENTITIESANDENTRIESSCRIPT, new SqlParameter("@EntityId", entityId));
        }

        private const string CleanupSecurityActivitiesScript = @"DELETE FROM EFMessages WHERE SavedAt < DATEADD(minute, -@TimeLimit, GETUTCDATE()) AND ExecutionState = 'Done'";
        internal void CleanupSecurityActivities(int timeLimitInMinutes)
        {
            this.Database.ExecuteSqlCommand(CleanupSecurityActivitiesScript, new SqlParameter("@TimeLimit", timeLimitInMinutes));
        }

        private static readonly string AcquireSecurityActivityExecutionLock_Script = @"UPDATE EFMessages
	SET ExecutionState = '" + ExecutionState.Executing + @"', LockedBy = @LockedBy, LockedAt = GETUTCDATE()
	WHERE Id = @ActivityId AND ((ExecutionState = '" + ExecutionState.Wait + @"') OR (ExecutionState = '" + ExecutionState.Executing + @"' AND LockedAt < DATEADD(second, -@TimeLimit, GETUTCDATE())))
IF (@@rowcount > 0)
	SELECT '" + ExecutionState.LockedForYou + @"'
ELSE
	SELECT ExecutionState FROM EFMessages WHERE Id = @ActivityId
";
        public string AcquireSecurityActivityExecutionLock(int securityActivityId, string lockedBy, int timeoutInSeconds)
        {
            var result = this.Database
                .SqlQuery<string>(
                    AcquireSecurityActivityExecutionLock_Script,
                    new SqlParameter("@ActivityId", securityActivityId),
                    new SqlParameter("@LockedBy", lockedBy ?? ""),
                    new SqlParameter("@TimeLimit", timeoutInSeconds)).Single();
            return result;
        }

        private static readonly string RefreshSecurityActivityExecutionLock_Script = @"UPDATE EFMessages SET LockedAt = GETUTCDATE() WHERE Id = @ActivityId";
        public void RefreshSecurityActivityExecutionLock(int securityActivityId)
        {
            this.Database
                .ExecuteSqlCommand(
                    RefreshSecurityActivityExecutionLock_Script,
                    new SqlParameter("@ActivityId", securityActivityId));
        }

        private static readonly string ReleaseSecurityActivityExecutionLock_Script = @"UPDATE EFMessages SET ExecutionState = '" + ExecutionState.Done + @"' WHERE Id = @ActivityId";
        public void ReleaseSecurityActivityExecutionLock(int securityActivityId)
        {
            this.Database
                .ExecuteSqlCommand(
                    ReleaseSecurityActivityExecutionLock_Script,
                    new SqlParameter("@ActivityId", securityActivityId));
        }

        private const string DeleteIdentity_Script = @"DELETE FROM EFMemberships WHERE GroupId = @IdentityId OR MemberId = @IdentityId
DELETE FROM EFEntries WHERE IdentityId = @IdentityId";
        internal void DeleteIdentity(int identityId)
        {
            this.Database.ExecuteSqlCommand(DeleteIdentity_Script, new SqlParameter("@IdentityId", identityId));
        }

        private const string DeleteIdentities_Script = @"
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
        internal void DeleteIdentities(IEnumerable<int> ids)
        {
            // construct an xml from the given id list for the sql command to make an id list on the SQL Server side
            var param = new SqlParameter("@IdentityList", SqlDbType.Xml)
            {
                Value = string.Format(IDLIST_XMLTEMPLATE, string.Join(string.Empty, ids.Select(identityId => string.Format(IDLISTITEM_XMLTEMPLATE, identityId))))
            };

            this.Database.ExecuteSqlCommand(DeleteIdentities_Script, param);
        }

        private const string RemoveMembers_Script = @"DELETE FROM EFMemberships WHERE GroupId = @GroupId AND MemberId IN ({0})";
        internal void RemoveMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers)
        {
            var sql = string.Format(RemoveMembers_Script, string.Join(", ", groupMembers.Union(userMembers)));
            this.Database.ExecuteSqlCommand(sql, new SqlParameter("@GroupId", groupId));
        }


        private const string IDLIST_XMLTEMPLATE = @"<Ids>{0}</Ids>";
        private const string IDLISTITEM_XMLTEMPLATE = @"<Id>{0}</Id>";

        private static string LoadResourceScript(string resourceName)
        {
            var assembly = Assembly.GetExecutingAssembly();

            using (var scriptStream = assembly.GetManifestResourceStream(resourceName))
            {
                if (scriptStream == null)
                    throw new ApplicationException("Script resource not found in the assembly: " + resourceName);

                using (var reader = new StreamReader(scriptStream))
                {
                    return reader.ReadToEnd();
                }
            }
        }
    }
}
