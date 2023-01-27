using SenseNet.Security.Messaging.SecurityMessages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
// ReSharper disable PossibleMultipleEnumeration

namespace SenseNet.Security
{
    public partial class SecurityContext
    {
        /*********************** Membership API **********************/

        /// <summary>
        /// Gets a flattened list of group ids that the current is member of.
        /// </summary>
        public virtual int[] GetFlattenedGroups()
        {
            return SecuritySystem.Cache.GetGroups(CurrentUser.Id);
        }
        /// <summary>
        /// Gets a flattened list of group ids that the current is member of, plus Everyone (except in case of a visitor) 
        /// and the optional dynamic groups provided by the client application.
        /// </summary>
        public virtual List<int> GetGroups()
        {
            return Evaluator.GetGroups(CurrentUser.Id, 0, 0).ToList();
        }
        /// <summary>
        /// Gets a flattened list of group ids that the current is member of, plus Everyone (except in case of a visitor),
        /// plus Owners (if applicable) and the optional dynamic groups provided by the client application.
        /// </summary>
        public virtual List<int> GetGroupsWithOwnership(int entityId)
        {
            return Evaluator.GetGroups(CurrentUser.Id, GetOwnerId(entityId), entityId).ToList();
        }

        /// <summary>
        /// Queries whether the provided member (user or group) is a member of a group. This method
        /// is transitive, meaning it will look for relations in the whole group graph, not 
        /// only direct memberships.
        /// </summary>
        public virtual bool IsInGroup(int memberId, int groupId)
        {
            return SecuritySystem.Cache.IsInGroup(memberId, groupId);
        }

        /// <summary>
        /// Adds different kinds of members to a group in one step.
        /// Non-existing groups or member groups will be created.
        /// If all the parameters are null or empty, nothing will happen.
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="userMembers">Collection of the user member identifiers. Can be null or empty.</param>
        /// <param name="groupMembers">Collection of the group member identifiers. Can be null or empty.</param>
        /// <param name="parentGroups">Collection of the parent group member identifiers. Use this if the parent 
        /// group or groups are already known when this method is called. Can be null or empty.</param>
        [Obsolete("Use async version instead.", true)]
        public virtual void AddMembersToSecurityGroup(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, IEnumerable<int> parentGroups = null)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(groupMembers, userMembers, parentGroups))
                return;
            var activity = new AddMembersToGroupActivity(groupId, userMembers, groupMembers, parentGroups);
            activity.Execute(this);
        }
        /// <summary>
        /// Adds different kinds of members to a group in one step.
        /// Non-existing groups or member groups will be created.
        /// If all the parameters are null or empty, nothing will happen.
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="userMembers">Collection of the user member identifiers. Can be null or empty.</param>
        /// <param name="groupMembers">Collection of the group member identifiers. Can be null or empty.</param>
        /// <param name="parentGroups">Collection of the parent group member identifiers. Use this if the parent 
        /// group or groups are already known when this method is called. Can be null or empty.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task AddMembersToSecurityGroupAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, CancellationToken cancel, IEnumerable<int> parentGroups = null)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(groupMembers, userMembers, parentGroups))
                return;
            var activity = new AddMembersToGroupActivity(groupId, userMembers, groupMembers, parentGroups);
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Removes multiple kinds of members from a group in one step.
        /// Non-existing groups or member groups will be skipped.
        /// If all the parameters are null or empty, nothing will happen.
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="userMembers">Collection of the user member identifiers. Can be null or empty.</param>
        /// <param name="groupMembers">Collection of the group member identifiers. Can be null or empty.</param>
        /// <param name="parentGroups">Collection of the parent group identifiers. Can be null or empty.</param>
        [Obsolete("Use async version instead.", true)]
        public virtual void RemoveMembersFromSecurityGroup(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, IEnumerable<int> parentGroups = null)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(groupMembers, userMembers, parentGroups))
                return;
            var activity = new RemoveMembersFromGroupActivity(groupId, userMembers, groupMembers, parentGroups);
            activity.Execute(this);
        }
        /// <summary>
        /// Removes multiple kinds of members from a group in one step.
        /// Non-existing groups or member groups will be skipped.
        /// If all the parameters are null or empty, nothing will happen.
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="userMembers">Collection of the user member identifiers. Can be null or empty.</param>
        /// <param name="groupMembers">Collection of the group member identifiers. Can be null or empty.</param>
        /// <param name="parentGroups">Collection of the parent group identifiers. Can be null or empty.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task RemoveMembersFromSecurityGroupAsync(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, CancellationToken cancel, IEnumerable<int> parentGroups = null)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(groupMembers, userMembers, parentGroups))
                return;
            var activity = new RemoveMembersFromGroupActivity(groupId, userMembers, groupMembers, parentGroups);
            await activity.ExecuteAsync(this, cancel);
        }

        /// <summary>
        /// Add one or more group members to a group. If the main group or any member is unknown it will be created.
        /// This method is a shortcut for AddMembersToSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="groupMembers">Collection of the group member identifiers. Can be null or empty.</param>
        [Obsolete("Use async version instead.", true)]
        public virtual void AddGroupsToSecurityGroup(int groupId, IEnumerable<int> groupMembers)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(groupMembers))
                return;
            var activity = new AddMembersToGroupActivity(groupId, null, groupMembers, null);
            activity.Execute(this);
        }
        /// <summary>
        /// Add one or more group members to a group. If the main group or any member is unknown it will be created.
        /// This method is a shortcut for AddMembersToSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="groupMembers">Collection of the group member identifiers. Can be null or empty.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task AddGroupsToSecurityGroupAsync(int groupId, IEnumerable<int> groupMembers, CancellationToken cancel)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(groupMembers))
                return;
            var activity = new AddMembersToGroupActivity(groupId, null, groupMembers, null);
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Add a group as a member of one or more parent groups. If the main group or any parent is unknown it will be created.
        /// This method is a shortcut for AddMembersToSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the member group. Cannot be 0.</param>
        /// <param name="parentGroups">Collection of the parent group identifiers. Can be null or empty.</param>
        [Obsolete("Use async version instead.", true)]
        public virtual void AddGroupToSecurityGroups(int groupId, IEnumerable<int> parentGroups)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(parentGroups))
                return;
            var activity = new AddMembersToGroupActivity(groupId, null, null, parentGroups);
            activity.Execute(this);
        }
        /// <summary>
        /// Add a group as a member of one or more parent groups. If the main group or any parent is unknown it will be created.
        /// This method is a shortcut for AddMembersToSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the member group. Cannot be 0.</param>
        /// <param name="parentGroups">Collection of the parent group identifiers. Can be null or empty.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task AddGroupToSecurityGroupsAsync(int groupId, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(parentGroups))
                return;
            var activity = new AddMembersToGroupActivity(groupId, null, null, parentGroups);
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Removes one or more group members from a group in one step.
        /// Non-existing group or member groups will be skipped.
        /// This method is a shortcut for RemoveMembersFromSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="groupMembers">Collection of the group member identifiers. Can be null or empty.</param>
        [Obsolete("Use async version instead.", true)]
        public virtual void RemoveGroupsFromSecurityGroup(int groupId, IEnumerable<int> groupMembers)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(groupMembers))
                return;
            var activity = new RemoveMembersFromGroupActivity(groupId, null, groupMembers, null);
            activity.Execute(this);
        }
        /// <summary>
        /// Removes one or more group members from a group in one step.
        /// Non-existing group or member groups will be skipped.
        /// This method is a shortcut for RemoveMembersFromSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="groupMembers">Collection of the group member identifiers. Can be null or empty.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task RemoveGroupsFromSecurityGroupAsync(int groupId, IEnumerable<int> groupMembers, CancellationToken cancel)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(groupMembers))
                return;
            var activity = new RemoveMembersFromGroupActivity(groupId, null, groupMembers, null);
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Removes a group from one or more parent groups
        /// Non-existing group or parent groups will be skipped.
        /// This method is a shortcut for RemoveMembersFromSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the member group. Cannot be 0.</param>
        /// <param name="parentGroups">Collection of the parent group identifiers. Can be null or empty.</param>
        [Obsolete("Use async version instead.", false)]
        public virtual void RemoveGroupFromSecurityGroups(int groupId, IEnumerable<int> parentGroups)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(parentGroups))
                return;
            var activity = new RemoveMembersFromGroupActivity(groupId, null, null, parentGroups);
            activity.Execute(this);
        }
        /// <summary>
        /// Removes a group from one or more parent groups
        /// Non-existing group or parent groups will be skipped.
        /// This method is a shortcut for RemoveMembersFromSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the member group. Cannot be 0.</param>
        /// <param name="parentGroups">Collection of the parent group identifiers. Can be null or empty.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task RemoveGroupFromSecurityGroupsAsync(int groupId, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(parentGroups))
                return;
            var activity = new RemoveMembersFromGroupActivity(groupId, null, null, parentGroups);
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Adds one or more users to a group in one step.
        /// Non-existing group will be created.
        /// This method is a shortcut for AddMembersToSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="userMembers">Collection of the user member identifiers. Can be null or empty.</param>
        [Obsolete("Use async version instead.", false)]
        public virtual void AddUsersToSecurityGroup(int groupId, IEnumerable<int> userMembers)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(userMembers))
                return;
            var activity = new AddMembersToGroupActivity(groupId, userMembers, null, null);
            activity.Execute(this);
        }
        /// <summary>
        /// Adds one or more users to a group in one step.
        /// Non-existing group will be created.
        /// This method is a shortcut for AddMembersToSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="userMembers">Collection of the user member identifiers. Can be null or empty.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task AddUsersToSecurityGroupAsync(int groupId, IEnumerable<int> userMembers, CancellationToken cancel)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(userMembers))
                return;
            var activity = new AddMembersToGroupActivity(groupId, userMembers, null, null);
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Add a user to one or more groups in one step.
        /// Non-existing groups will be created.
        /// </summary>
        /// <param name="userId">Identifier of the the user member that will be added. Cannot be 0.</param>
        /// <param name="parentGroups">Collection of the parent group identifiers. Can be null or empty.</param>
        [Obsolete("Use async version instead.", false)]
        public virtual void AddUserToSecurityGroups(int userId, IEnumerable<int> parentGroups)
        {
            if (userId == default)
                throw new ArgumentException("The userId cannot be " + default(int));
            if (AllNullOrEmpty(parentGroups))
                return;
            var activity = new AddUserToSecurityGroupsActivity(userId, parentGroups);
            activity.Execute(this);
        }
        /// <summary>
        /// Add a user to one or more groups in one step.
        /// Non-existing groups will be created.
        /// </summary>
        /// <param name="userId">Identifier of the the user member that will be added. Cannot be 0.</param>
        /// <param name="parentGroups">Collection of the parent group identifiers. Can be null or empty.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task AddUserToSecurityGroupsAsync(int userId, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            if (userId == default)
                throw new ArgumentException("The userId cannot be " + default(int));
            if (AllNullOrEmpty(parentGroups))
                return;
            var activity = new AddUserToSecurityGroupsActivity(userId, parentGroups);
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Removes one or more users from a group in one step.
        /// Non-existing group or member will be skipped.
        /// This method is a shortcut for RemoveMembersFromSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="userMembers">Collection of the user member identifiers. Can be null or empty.</param>
        [Obsolete("Use async version instead.", false)]
        public virtual void RemoveUsersFromSecurityGroup(int groupId, IEnumerable<int> userMembers)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(userMembers))
                return;
            var activity = new RemoveMembersFromGroupActivity(groupId, userMembers, null, null);
            activity.Execute(this);
        }
        /// <summary>
        /// Removes one or more users from a group in one step.
        /// Non-existing group or member will be skipped.
        /// This method is a shortcut for RemoveMembersFromSecurityGroup(...).
        /// </summary>
        /// <param name="groupId">Identifier of the container group. Cannot be 0.</param>
        /// <param name="userMembers">Collection of the user member identifiers. Can be null or empty.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task RemoveUsersFromSecurityGroupAsync(int groupId, IEnumerable<int> userMembers, CancellationToken cancel)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            if (AllNullOrEmpty(userMembers))
                return;
            var activity = new RemoveMembersFromGroupActivity(groupId, userMembers, null, null);
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Removes a user from one or more groups in one step.
        /// Non-existing group or member will be skipped.
        /// </summary>
        /// <param name="userId">Identifier of the user the will be removed. Cannot be 0.</param>
        /// <param name="parentGroups">Collection of the parent group identifiers. Can be null or empty.</param>
        [Obsolete("Use async version instead.", false)]
        public virtual void RemoveUserFromSecurityGroups(int userId, IEnumerable<int> parentGroups)
        {
            if (userId == default)
                throw new ArgumentException("The userId cannot be " + default(int));
            if (AllNullOrEmpty(parentGroups))
                return;
            var activity = new RemoveUserFromSecurityGroupsActivity(userId, parentGroups);
            activity.Execute(this);
        }
        /// <summary>
        /// Removes a user from one or more groups in one step.
        /// Non-existing group or member will be skipped.
        /// </summary>
        /// <param name="userId">Identifier of the user the will be removed. Cannot be 0.</param>
        /// <param name="parentGroups">Collection of the parent group identifiers. Can be null or empty.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task RemoveUserFromSecurityGroupsAsync(int userId, IEnumerable<int> parentGroups, CancellationToken cancel)
        {
            if (userId == default)
                throw new ArgumentException("The userId cannot be " + default(int));
            if (AllNullOrEmpty(parentGroups))
                return;
            var activity = new RemoveUserFromSecurityGroupsActivity(userId, parentGroups);
            await activity.ExecuteAsync(this, cancel);
        }

        /// <summary>
        /// Deletes the specified group and its relations including related security entries.
        /// </summary>
        [Obsolete("Use async version instead.", false)]
        public virtual void DeleteSecurityGroup(int groupId)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            var activity = new DeleteGroupActivity(groupId);
            activity.Execute(this);
        }

        /// <summary>
        /// Deletes the specified group and its relations including related security entries.
        /// </summary>
        /// <param name="groupId">The Id of the group to be deleted.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task DeleteSecurityGroupAsync(int groupId, CancellationToken cancel)
        {
            if (groupId == default)
                throw new ArgumentException("The groupId cannot be " + default(int));
            var activity = new DeleteGroupActivity(groupId);
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Deletes the user from the system by removing all memberships and security entries related to this user.
        /// </summary>
        [Obsolete("Use async version instead.", false)]
        public virtual void DeleteUser(int userId)
        {
            if (userId == default)
                throw new ArgumentException("The userId cannot be " + default(int));
            var activity = new DeleteUserActivity(userId);
            activity.Execute(this);
        }

        /// <summary>
        /// Deletes the user from the system by removing all memberships and security entries related to this user.
        /// </summary>
        /// <param name="userId">The Id of the user to be deleted.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task DeleteUserAsync(int userId, CancellationToken cancel)
        {
            if (userId == default)
                throw new ArgumentException("The userId cannot be " + default(int));
            var activity = new DeleteUserActivity(userId);
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Deletes the specified group or user and its relations including related security entries.
        /// </summary>
        [Obsolete("Use async version instead.", false)]
        public virtual void DeleteIdentity(int id)
        {
            if (id == default)
                throw new ArgumentException("The id cannot be " + default(int));
            var activity = new DeleteIdentitiesActivity(new[] { id });
            activity.Execute(this);
        }

        /// <summary>
        /// Deletes the specified group or user and its relations including related security entries.
        /// </summary>
        /// <param name="id">The Id of the identity to be deleted.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task DeleteIdentityAsync(int id, CancellationToken cancel)
        {
            if (id == default)
                throw new ArgumentException("The id cannot be " + default(int));
            var activity = new DeleteIdentitiesActivity(new[] { id });
            await activity.ExecuteAsync(this, cancel);
        }
        /// <summary>
        /// Deletes the specified groups or users and their relations including related security entries.
        /// </summary>
        [Obsolete("Use async version instead.", false)]
        public virtual void DeleteIdentities(IEnumerable<int> ids)
        {
            if (ids == null)
                throw new ArgumentException("ids");
            var activity = new DeleteIdentitiesActivity(ids);
            activity.Execute(this);
        }

        /// <summary>
        /// Deletes the specified groups or users and their relations including related security entries.
        /// </summary>
        /// <param name="ids">Set of identity Ids to be deleted.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task DeleteIdentitiesAsync(IEnumerable<int> ids, CancellationToken cancel)
        {
            if (ids == null)
                throw new ArgumentException("ids");
            var activity = new DeleteIdentitiesActivity(ids);
            await activity.ExecuteAsync(this, cancel);
        }

        private bool AllNullOrEmpty(params IEnumerable<int>[] args)
        {
            return !args.Any(a => a != null && a.FirstOrDefault() != default);
        }

        /*********************** Membership extension API **********************/

        /// <summary>
        /// Gets the list of additional group ids for the user dynamically defined by the client application.
        /// </summary>
        internal IEnumerable<int> GetDynamicGroups(int entityId)
        {
            return CurrentUser.GetDynamicGroups(entityId);
        }
    }
}
