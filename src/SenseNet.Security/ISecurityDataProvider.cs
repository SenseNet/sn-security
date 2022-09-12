using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents a query result of the query group-related entities.
    /// </summary>
    public class GroupRelatedEntitiesQueryResult
    {
        /// <summary>
        /// Gets or sets a collection of entity ids that have a group-related access control entry.
        /// </summary>
        public IEnumerable<int> EntityIds { get; set; }
        /// <summary>
        /// Entities that have only the given group related ACEs. These ACLs will be removed.
        /// </summary>
        public IEnumerable<int> ExclusiveEntityIds { get; set; }
    }

    public class SaveSecurityActivityResult
    {
        /// <summary>
        /// Gets or sets the id of the saved activity.
        /// </summary>
        public int ActivityId { get; set; }
        /// <summary>
        /// Gets or sets the size of the activity body in bytes.
        /// </summary>
        public int BodySize { get; set; }
    }

    /// <summary>
    /// Describes a customizable storage layer interface of the Security Component.
    /// </summary>
    public interface ISecurityDataProvider
    {
        /// <summary>
        /// Control data for building a connection to the database server.
        /// </summary>
        // ReSharper disable once UnusedMemberInSuper.Global
        string ConnectionString { get; set; }

        /// <summary>
        /// Gets or sets the ActivitySerializer for loading activities.
        /// </summary>
        IActivitySerializer ActivitySerializer { get; set; }

        /// <summary>
        /// Creates the database schema and other components (tables, etc.). It requires an existing database.
        /// </summary>
        // ReSharper disable once UnusedMemberInSuper.Global
        void InstallDatabase();

        /// <summary>
        /// Checks if the database exists and is ready to accept new items.
        /// If this method returns false, the client should install the database first.
        /// </summary>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        Task<bool> IsDatabaseReadyAsync(CancellationToken cancel);

        /******************************************* structure pre-loaders */

        /// <summary>
        /// Pre-loader method for retrieving all stored SecurityEntity. Called during system start.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        IEnumerable<StoredSecurityEntity> LoadSecurityEntities();
        /// <summary>
        /// Async pre-loader method for retrieving all stored SecurityEntity. Called during system start.
        /// </summary>
        Task<IEnumerable<StoredSecurityEntity>> LoadSecurityEntitiesAsync(CancellationToken cancel);

        /// <summary>
        /// Loads the set of security holder entity ids.
        /// This is a distinct int list of entities in entries plus entities that are not inherited (IsInherited = false).
        /// </summary>
        IEnumerable<int> LoadAffectedEntityIdsByEntriesAndBreaks();
        /// <summary>
        /// Asynchronously loads the set of security holder entity ids.
        /// This is a distinct int list of entities in entries plus entities that are not inherited (IsInherited = false).
        /// </summary>
        Task<IEnumerable<int>> LoadAffectedEntityIdsByEntriesAndBreaksAsync(CancellationToken cancel);

        /// <summary>
        /// Loader method for retrieving all ACE-s. Called during system start.
        /// </summary>
        IEnumerable<StoredAce> LoadAllAces();
        //UNDONE:x: Async version of LoadAllAces (uses yield)

        /******************************************* structure storage */

        /// <summary>
        /// Retrieves the SecurityEntity by the passed identifier. Returns with null if the entity was not found.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        StoredSecurityEntity LoadStoredSecurityEntity(int entityId);
        /// <summary>
        /// Asynchronously retrieves the SecurityEntity by the passed identifier. Returns with null if the entity was not found.
        /// </summary>
        Task<StoredSecurityEntity> LoadStoredSecurityEntityAsync(int entityId, CancellationToken cancel);

        /// <summary>
        /// Writes the given entity to the database. If it exists before writing, the operation will be skipped.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void InsertSecurityEntity(StoredSecurityEntity entity);
        /// <summary>
        /// Asynchronously writes the given entity to the database. If it exists before writing, the operation will be skipped.
        /// </summary>
        Task InsertSecurityEntityAsync(StoredSecurityEntity entity, CancellationToken cancel);

        /// <summary>
        /// Updates the given entity to the database. If it does not exist before updating, a SecurityStructureException must be thrown.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void UpdateSecurityEntity(StoredSecurityEntity entity);
        /// <summary>
        /// Asynchronously updates the given entity to the database. If it does not exist before updating, a SecurityStructureException must be thrown.
        /// </summary>
        Task UpdateSecurityEntityAsync(StoredSecurityEntity entity, CancellationToken cancel);

        /// <summary>
        /// Deletes an entity by the given identifier. If the entity does not exist before deleting, this method does nothing.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void DeleteSecurityEntity(int entityId);
        /// <summary>
        /// Asynchronously deletes an entity by the given identifier. If the entity does not exist before deleting, this method does nothing.
        /// </summary>
        Task DeleteSecurityEntityAsync(int entityId, CancellationToken cancel);

        /// <summary>
        /// Moves the source entity to the target entity. Only a parent relink is needed. All other operations call other data provider methods.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void MoveSecurityEntity(int sourceId, int targetId);
        /// <summary>
        /// Asynchronously moves the source entity to the target entity. Only a parent relink is needed. All other operations call other data provider methods.
        /// </summary>
        Task MoveSecurityEntityAsync(int sourceId, int targetId, CancellationToken cancel);

        /******************************************* membership storage */

        /// <summary>
        /// Pre-loader method for retrieving all stored SecurityGroups. Called during system start.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        IEnumerable<SecurityGroup> LoadAllGroups();
        /// <summary>
        /// Async pre-loader method for retrieving all stored SecurityGroups. Called during system start.
        /// </summary>
        Task<IEnumerable<SecurityGroup>> LoadAllGroupsAsync(CancellationToken cancel);

        /// <summary>
        /// Loads a SecurityGroup from the database.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        SecurityGroup LoadSecurityGroup(int groupId);
        /// <summary>
        /// Asynchronously loads a SecurityGroup from the database.
        /// </summary>
        Task<SecurityGroup> LoadSecurityGroupAsync(int groupId, CancellationToken cancel);

        /// <summary>
        /// Provides a collection of entity ids that have a group-related access control entry.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="entityIds">Entities that have one or more group related ACEs. These ACEs will be removed from the ACLs.</param>
        /// <param name="exclusiveEntityIds">Entities that have only the given group related ACEs. These ACLs will be removed.</param>
        void QueryGroupRelatedEntities(int groupId, out IEnumerable<int> entityIds, out IEnumerable<int> exclusiveEntityIds);
        /// <summary>
        /// Asynchronously provides a collection of entity ids that have a group-related access control entry.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        Task<GroupRelatedEntitiesQueryResult> QueryGroupRelatedEntitiesAsync(int groupId, CancellationToken cancel);

        /*--------------------------------------------------------------*/

        /// <summary>
        /// Deletes memberships and entries related to an identity.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void DeleteIdentityAndRelatedEntries(int identityId);
        /// <summary>
        /// Asynchronously deletes memberships and entries related to an identity.
        /// </summary>
        Task DeleteIdentityAndRelatedEntriesAsync(int identityId, CancellationToken cancel);

        /// <summary>
        /// Deletes memberships and entries related to the provided identities.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void DeleteIdentitiesAndRelatedEntries(IEnumerable<int> ids);
        /// <summary>
        /// Asynchronously deletes memberships and entries related to the provided identities.
        /// </summary>
        Task DeleteIdentitiesAndRelatedEntriesAsync(IEnumerable<int> ids, CancellationToken cancel);

        /// <summary>
        /// Adds one or more users and groups to the specified group.
        /// </summary>
        /// <param name="groupId">Id of the group that will have new members.</param>
        /// <param name="userMembers">Contains the ids of new users. Can be null or an empty list too.</param>
        /// <param name="groupMembers">Contains the ids of new groups. Can be null or an empty list too.</param>
        [Obsolete("Use async version instead.", true)]
        void AddMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers);
        /// <summary>
        /// Asynchronously adds one or more users and groups to the specified group.
        /// </summary>
        /// <param name="groupId">Id of the group that will have new members.</param>
        /// <param name="userMembers">Contains the ids of new users. Can be null or an empty list too.</param>
        /// <param name="groupMembers">Contains the ids of new groups. Can be null or an empty list too.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        Task AddMembersAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, CancellationToken cancel);

        /// <summary>
        /// Removes one or more users and groups from the specified group.
        /// </summary>
        /// <param name="groupId">Id of a group.</param>
        /// <param name="userMembers">Contains the ids of users that will be removed. Can be null or an empty list too.</param>
        /// <param name="groupMembers">Contains the ids of groups that will be removed. Can be null or an empty list too.</param>
        [Obsolete("Use async version instead.", true)]
        void RemoveMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers);
        /// <summary>
        /// Asynchronously removes one or more users and groups from the specified group.
        /// </summary>
        /// <param name="groupId">Id of a group.</param>
        /// <param name="userMembers">Contains the ids of users that will be removed. Can be null or an empty list too.</param>
        /// <param name="groupMembers">Contains the ids of groups that will be removed. Can be null or an empty list too.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        Task RemoveMembersAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, CancellationToken cancel);

        /******************************************* storing and caching permission entries */

        /// <summary>
        /// Returns all stored ACEs that exist in the database in an unordered list.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        IEnumerable<StoredAce> LoadAllPermissionEntries();
        /// <summary>
        /// Asynchronously returns all stored ACEs that exist in the database in an unordered list.
        /// </summary>
        Task<IEnumerable<StoredAce>> LoadAllPermissionEntriesAsync(CancellationToken cancel);

        /// <summary>
        /// Loads an ACL-chain. Caller provides the parent chain of an entity.
        /// This method must return with all stored ACEs that belong to any of the passed entity ids.
        /// Order is irrelevant.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        IEnumerable<StoredAce> LoadPermissionEntries(IEnumerable<int> entityIds);
        /// <summary>
        /// Asynchronously loads an ACL-chain. Caller provides the parent chain of an entity.
        /// This method must return with all stored ACEs that belong to any of the passed entity ids.
        /// Order is irrelevant.
        /// </summary>
        Task<IEnumerable<StoredAce>> LoadPermissionEntriesAsync(IEnumerable<int> entityIds, CancellationToken cancel);

        /// <summary>
        /// Returns the estimated security entity count as fast as possible.
        /// System start sequence uses this method.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        int GetEstimatedEntityCount();
        /// <summary>
        /// Asynchronously returns the estimated security entity count as fast as possible.
        /// System start sequence uses this method.
        /// </summary>
        Task<int> GetEstimatedEntityCountAsync(CancellationToken cancel);

        /// <summary>
        /// Inserts or updates one or more StoredACEs.
        /// An ACE is identified by a compound key: EntityId, EntryType, IdentityId, LocalOnly
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void WritePermissionEntries(IEnumerable<StoredAce> aces);
        /// <summary>
        /// Asynchronously inserts or updates one or more StoredACEs.
        /// An ACE is identified by a compound key: EntityId, EntryType, IdentityId, LocalOnly
        /// </summary>
        Task WritePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel);

        /// <summary>
        /// Deletes the given ACEs.  If an ACE does not exist before deleting, it must be skipped.
        /// An ACE is identified by a compound key: EntityId, EntryType, IdentityId, LocalOnly
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void RemovePermissionEntries(IEnumerable<StoredAce> aces);
        /// <summary>
        /// Asynchronously deletes the given ACEs.  If an ACE does not exist before deleting, it must be skipped.
        /// An ACE is identified by a compound key: EntityId, EntryType, IdentityId, LocalOnly
        /// </summary>
        Task RemovePermissionEntriesAsync(IEnumerable<StoredAce> aces, CancellationToken cancel);

        /// <summary>
        /// Deletes all ACEs related to the given entity id.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void RemovePermissionEntriesByEntity(int entityId);
        /// <summary>
        /// Asynchronously deletes all ACEs related to the given entity id.
        /// </summary>
        Task RemovePermissionEntriesByEntityAsync(int entityId, CancellationToken cancel);

        /// <summary>
        /// Deletes all ACEs related to any of the entities in a subtree defined by the provided root id, then deletes all the entities too.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void DeleteEntitiesAndEntries(int entityId);
        /// <summary>
        /// Asynchronously deletes all ACEs related to any of the entities in a subtree defined by the provided root id, then deletes all the entities too.
        /// </summary>
        Task DeleteEntitiesAndEntriesAsync(int entityId, CancellationToken cancel);

        /// <summary>
        /// Stores the full data of the passed activity.
        /// Returns with the generated activity id and the size of the activity's body. 
        /// Activity ids in the database must be a consecutive list of numbers.
        /// </summary>
        /// <param name="activity">Activity to save.</param>
        /// <param name="bodySize">Activity size in bytes.</param>
        /// <returns>The generated activity id.</returns>
        [Obsolete("Use async version instead.", true)]
        int SaveSecurityActivity(Messaging.SecurityMessages.SecurityActivity activity, out int bodySize);
        /// <summary>
        /// Asynchronously stores the full data of the passed activity.
        /// Returns with the generated activity id and the size of the activity's body. 
        /// Activity ids in the database must be a consecutive list of numbers.
        /// </summary>
        /// <param name="activity">Activity to save.</param>
        /// <param name="cancel">Activity size in bytes.</param>
        /// <returns>The generated activity id and its size in one <see cref="SaveSecurityActivityResult"/> instance.</returns>
        Task<SaveSecurityActivityResult> SaveSecurityActivityAsync(Messaging.SecurityMessages.SecurityActivity activity,
            CancellationToken cancel);

        /// <summary>
        /// Returns the biggest activity id that was saved before the provided time if there is any.
        /// Otherwise returns with 0.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        int GetLastSecurityActivityId(DateTime startedTime);
        /// <summary>
        /// Asynchronously returns the biggest activity id that was saved before the provided time if there is any.
        /// Otherwise returns with 0.
        /// </summary>
        Task<int> GetLastSecurityActivityIdAsync(DateTime startedTime, CancellationToken cancel);

        /// <summary>
        /// Returns an array of all unprocessed activity ids supplemented with the last stored activity id.
        /// Empty array means that the database does not contain any activities.
        /// Array with only one element means that the database does not contain any unprocessed element and the last stored activity id is the returned item.
        /// Two or more element means that the array contains one or more unprocessed activity id and the last element is the last stored activity id.
        /// </summary>
        /// <returns>Zero or more id of unprocessed elements supplemented with the last stored activity id.</returns>
        [Obsolete("Use async version instead.", true)]
        int[] GetUnprocessedActivityIds();
        /// <summary>
        /// Asynchronously returns an array of all unprocessed activity ids supplemented with the last stored activity id.
        /// Empty array means that the database does not contain any activities.
        /// Array with only one element means that the database does not contain any unprocessed element and the last stored activity id is the returned item.
        /// Two or more element means that the array contains one or more unprocessed activity id and the last element is the last stored activity id.
        /// </summary>
        /// <returns>Zero or more id of unprocessed elements supplemented with the last stored activity id.</returns>
        Task<int[]> GetUnprocessedActivityIdsAsync(CancellationToken cancel);

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
        /// <param name="executingUnprocessedActivities">Value of the IsUnprocessedActivity property of every loaded object.</param>
        [Obsolete("Use async version instead.", true)] 
        Messaging.SecurityMessages.SecurityActivity[] LoadSecurityActivities(int from, int to, int count, bool executingUnprocessedActivities);
        /// <summary>
        /// Asynchronously loads a SecurityActivity fragment within the specified limits.
        /// If the count of activities in the id boundary ("from", "to") is bigger
        /// than the given fragment size ("count"), the largest id could not reach.
        /// Activities in the result array are sorted by id.
        /// Value of the IsUnprocessedActivity property of every loaded object
        /// will be the value of the given "executingUnprocessedActivities" parameter.
        /// </summary>
        /// <param name="from">Least expected id.</param>
        /// <param name="to">Largest allowed id.</param>
        /// <param name="count">Fragment size.</param>
        /// <param name="executingUnprocessedActivities">Value of the IsUnprocessedActivity property of every loaded object.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        Task<Messaging.SecurityMessages.SecurityActivity[]> LoadSecurityActivitiesAsync(int from, int to, int count,
            bool executingUnprocessedActivities, CancellationToken cancel);

        /// <summary>
        /// Loads a SecurityActivity fragment by the individual id array.
        /// Activities in the result array are sorted by id.
        /// Value of the IsUnprocessedActivity property of every loaded object
        /// will be the value of the given "executingUnprocessedActivities" parameter.
        /// </summary>
        /// <param name="gaps">Individual id array</param>
        /// <param name="executingUnprocessedActivities">Value of the IsUnprocessedActivity property of every loaded object.</param>
        [Obsolete("Use async version instead.", true)]
        Messaging.SecurityMessages.SecurityActivity[] LoadSecurityActivities(int[] gaps, bool executingUnprocessedActivities);

        /// <summary>
        /// Asynchronously loads a SecurityActivity fragment by the individual id array.
        /// Activities in the result array are sorted by id.
        /// Value of the IsUnprocessedActivity property of every loaded object
        /// will be the value of the given "executingUnprocessedActivities" parameter.
        /// </summary>
        /// <param name="gaps">Individual id array</param>
        /// <param name="executingUnprocessedActivities">Value of the IsUnprocessedActivity property of every loaded object.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        Task<Messaging.SecurityMessages.SecurityActivity[]> LoadSecurityActivitiesAsync(int[] gaps,
            bool executingUnprocessedActivities, CancellationToken cancel);

        /// <summary>
        /// Returns a SecurityActivity.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        Messaging.SecurityMessages.SecurityActivity LoadSecurityActivity(int id);
        /// <summary>
        /// Asynchronously returns a SecurityActivity.
        /// </summary>
        Task<Messaging.SecurityMessages.SecurityActivity> LoadSecurityActivityAsync(int id, CancellationToken cancel);

        /// <summary>
        /// Deletes all the activities that were saved before the given time limit.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void CleanupSecurityActivities(int timeLimitInMinutes);
        /// <summary>
        /// Asynchronously deletes all the activities that were saved before the given time limit.
        /// </summary>
        Task CleanupSecurityActivitiesAsync(int timeLimitInMinutes, CancellationToken cancel);

        /// <summary>
        /// Ensures an exclusive (only one) object for the activity. Returns the new lock object or null.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        Messaging.SecurityActivityExecutionLock AcquireSecurityActivityExecutionLock(Messaging.SecurityMessages.SecurityActivity securityActivity, int timeoutInSeconds);
        /// <summary>
        /// Asynchronously ensures an exclusive (only one) object for the activity. Returns the new lock object or null.
        /// </summary>
        Task<Messaging.SecurityActivityExecutionLock> AcquireSecurityActivityExecutionLockAsync(
            Messaging.SecurityMessages.SecurityActivity securityActivity, int timeoutInSeconds, CancellationToken cancel);

        /// <summary>
        /// Refreshes the lock object to avoid its timeout.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void RefreshSecurityActivityExecutionLock(Messaging.SecurityMessages.SecurityActivity securityActivity);
        /// <summary>
        /// Asynchronously refreshes the lock object to avoid its timeout.
        /// </summary>
        Task RefreshSecurityActivityExecutionLockAsync(Messaging.SecurityMessages.SecurityActivity securityActivity, CancellationToken cancel);

        /// <summary>
        /// Releases the lock and prevents locking that activity again by setting its state to Executed.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        void ReleaseSecurityActivityExecutionLock(Messaging.SecurityMessages.SecurityActivity securityActivity);
        /// <summary>
        /// Asynchronously releases the lock and prevents locking that activity again by setting its state to Executed.
        /// </summary>
        Task ReleaseSecurityActivityExecutionLockAsync(Messaging.SecurityMessages.SecurityActivity securityActivity, CancellationToken cancel);

        /// <summary>
        /// Returns with information for consistency check: a compound number containing the group's and the member's id.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        IEnumerable<long> GetMembershipForConsistencyCheck();
        /// <summary>
        /// Asynchronously returns with information for consistency check: a compound number containing the group's and the member's id.
        /// </summary>
        Task<IEnumerable<long>> GetMembershipForConsistencyCheckAsync(CancellationToken cancel);
    }
}
