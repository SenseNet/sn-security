using System;
using System.Collections.Generic;

namespace SenseNet.Security
{
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
        /// Creator method. Returns a brand new ISecurityDataProvider instance
        /// </summary>
        ISecurityDataProvider CreateNew();

        /// <summary>
        /// Empties the entire database (clears all records from all tables).
        /// </summary>
        void DeleteEverything();

        /// <summary>
        /// Creates the database schema and other components (tables, etc.). It requires an existing database.
        /// </summary>
        // ReSharper disable once UnusedMemberInSuper.Global
        void InstallDatabase();

        /******************************************* structure preloaders */

        /// <summary>
        /// Preloader method for retrieving all stored SecurityEntity. Called during system start.
        /// </summary>
        IEnumerable<StoredSecurityEntity> LoadSecurityEntities();
        /// <summary>
        /// Loads the set of security holder entity ids.
        /// This is a distincted int list of entities in entries plus entities that are not inherited (IsInherited = false).
        /// </summary>
        IEnumerable<int> LoadAffectedEntityIdsByEntriesAndBreaks();
        /// <summary>
        /// Loader method for retrieving all ACE-s. Called during system start.
        /// </summary>
        IEnumerable<StoredAce> LoadAllAces();

        /******************************************* structure storage */

        /// <summary>
        /// Retrieves the SecurityEntity by the passed identifier. Returns with null if the entity was not found.
        /// </summary>
        StoredSecurityEntity LoadStoredSecurityEntity(int entityId);

        /// <summary>
        /// Writes the given entity to the database. If it exists before writing, the operation will be skipped.
        /// </summary>
        void InsertSecurityEntity(StoredSecurityEntity entity);
        /// <summary>
        /// Updates the given entity to the database. If it does not exist before updating, a SecurityStructureException must be thrown.
        /// </summary>
        void UpdateSecurityEntity(StoredSecurityEntity entity);

        /// <summary>
        /// Deletes an entity by the given identifier. If the entity does not exist before deleting, this method does nothing.
        /// </summary>
        void DeleteSecurityEntity(int entityId);
        /// <summary>
        /// Moves the source entity to the target entity. Only a parent relink is needed. All other operations call other data provider methods.
        /// </summary>
        void MoveSecurityEntity(int sourceId, int targetId);


        /******************************************* membership storage */

        /// <summary>
        /// Preloader method for retrieving all stored SecurityGroups. Called during system start.
        /// </summary>
        IEnumerable<SecurityGroup> LoadAllGroups();

        /// <summary>
        /// Loads a SecurityGroup from the database.
        /// </summary>
        SecurityGroup LoadSecurityGroup(int groupId);

        /// <summary>
        /// This method provides a collection of entity ids that have a group-related access control entry.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="entityIds">Entities that have one or more group related ACEs. These ACEs will be removed from the ACLs.</param>
        /// <param name="exclusiveEntityIds">Entities that have only the given group related ACEs. These ACLs will be removed.</param>
        void QueryGroupRelatedEntities(int groupId, out IEnumerable<int> entityIds, out IEnumerable<int> exclusiveEntityIds);

        /*--------------------------------------------------------------*/

        /// <summary>
        /// Deletes memberships and entries related to an identity.
        /// </summary>
        void DeleteIdentityAndRelatedEntries(int identityId);

        /// <summary>
        /// Deletes memberships and entries related to the provided identities.
        /// </summary>
        void DeleteIdentitiesAndRelatedEntries(IEnumerable<int> ids);

        /// <summary>
        /// Adds one or more users and groups to the specified group.
        /// </summary>
        /// <param name="groupId">Id of the group that will have new members.</param>
        /// <param name="userMembers">Contains the ids of new users. Can be null or an empty list too.</param>
        /// <param name="groupMembers">Contains the ids of new groups. Can be null or an empty list too.</param>
        void AddMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers);

        /// <summary>
        /// Removes one or more users and groups from the specified group.
        /// </summary>
        /// <param name="groupId">Id of a group.</param>
        /// <param name="userMembers">Contains the ids of users that will be removed. Can be null or an empty list too.</param>
        /// <param name="groupMembers">Contains the ids of groups that will be removed. Can be null or an empty list too.</param>
        void RemoveMembers(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers);

        /******************************************* storing and caching permission entries */

        /// <summary>
        /// This method must return with all stored ACEs that exist in the database in an unordered list.
        /// </summary>
        IEnumerable<StoredAce> LoadAllPermissionEntries();

        /// <summary>
        /// Loads an ACL-chain. Caller provides the parent chain of an entity.
        /// This method must return with all stored ACEs that belong to any of the passed entity ids.
        /// Order is irrelevant.
        /// </summary>
        IEnumerable<StoredAce> LoadPermissionEntries(IEnumerable<int> entityIds);

        /// <summary>
        /// Returns with the estimated security entity count as fast as possible.
        /// System start sequence uses this method.
        /// </summary>
        int GetEstimatedEntityCount();

        /// <summary>
        /// Inserts or updates one or more StoredACEs.
        /// An ACE is identified by a compound key: EntityId, EntryType, IdentityId, LocalOnly
        /// </summary>
        void WritePermissionEntries(IEnumerable<StoredAce> aces);
        /// <summary>
        /// Deletes the given ACEs.  If an ACE does not exist before deleting, it must be skipped.
        /// An ACE is identified by a compound key: EntityId, EntryType, IdentityId, LocalOnly
        /// </summary>
        void RemovePermissionEntries(IEnumerable<StoredAce> aces);

        /// <summary>
        /// Deletes all ACEs related to the given entity id.
        /// </summary>
        void RemovePermissionEntriesByEntity(int entityId);

        /// <summary>
        /// Deletes all ACEs related to any of the entities in a subtree defined by the provided root id, then deletes all the entities too.
        /// </summary>
        void DeleteEntitiesAndEntries(int entityId);

        /// <summary>
        /// Stores the full data of the passed activity.
        /// Returns with the generated activity id and the size of the activity's body. 
        /// Activity ids in the database must be a consecutive list of numbers.
        /// </summary>
        /// <param name="activity">Activity to save.</param>
        /// <param name="bodySize">Activity size in bytes.</param>
        /// <returns>The generated activity id.</returns>
        int SaveSecurityActivity(Messaging.SecurityMessages.SecurityActivity activity, out int bodySize);

        /// <summary>
        /// Returns the biggest activity id that was saved before the provided time if there is any.
        /// Otherwise returns with 0.
        /// </summary>
        int GetLastSecurityActivityId(DateTime startedTime);

        /// <summary>
        /// Returns an array of all unprocessed activity ids supplemented with the last stored activity id.
        /// Empty array means that the database does not contain any activities.
        /// Array with only one element means that the database does not contain any unprocessed element and the last stored activity id is the returned item.
        /// Two or more element means that the array contains one or more unprocessed activity id and the last element is the last stored activity id.
        /// </summary>
        /// <returns>Zero or more id of unprocessed elements supplemented with the last stored activity id.</returns>
        int[] GetUnprocessedActivityIds();

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
        /// <param name="executingUnprocessedActivities">Value of the IsUnprocessedActivity property of every loaded object.</param>
        Messaging.SecurityMessages.SecurityActivity[] LoadSecurityActivities(int from, int to, int count, bool executingUnprocessedActivities);

        /// <summary>
        /// Loads a SecurityActivity fragment by the individual id array.
        /// Activities in the result array are sorted by id.
        /// Value of the IsUnprocessedActivity property of every loaded object
        /// vill be the value of the given "executingUnprocessedActivities" parameter.
        /// </summary>
        /// <param name="gaps">Individual id array</param>
        /// <param name="executingUnprocessedActivities">Value of the IsUnprocessedActivity property of every loaded object.</param>
        Messaging.SecurityMessages.SecurityActivity[] LoadSecurityActivities(int[] gaps, bool executingUnprocessedActivities);

        /// <summary>
        /// Returns a SecurityActivity.
        /// </summary>
        Messaging.SecurityMessages.SecurityActivity LoadSecurityActivity(int id);

        /// <summary>
        /// Deletes all the activities that were saved before the given time limit.
        /// </summary>
        void CleanupSecurityActivities(int timeLimitInMinutes);

        /// <summary>
        /// Ensures an exclusive (only one) object for the activity. Returns the new lock object or null.
        /// </summary>
        Messaging.SecurityActivityExecutionLock AcquireSecurityActivityExecutionLock(Messaging.SecurityMessages.SecurityActivity securityActivity, int timeoutInSeconds);

        /// <summary>
        /// Refreshes the lock object to avoid its timeout.
        /// </summary>
        void RefreshSecurityActivityExecutionLock(Messaging.SecurityMessages.SecurityActivity securityActivity);

        /// <summary>
        /// Releases the lock and prevents locking that activity again by setting its state to Executed.
        /// </summary>
        void ReleaseSecurityActivityExecutionLock(Messaging.SecurityMessages.SecurityActivity securityActivity);

        /// <summary>
        /// Returns with information for consistency check: a compound number containing the group's and the member's id.
        /// </summary>
        IEnumerable<long> GetMembershipForConsistencyCheck();
    }
}
