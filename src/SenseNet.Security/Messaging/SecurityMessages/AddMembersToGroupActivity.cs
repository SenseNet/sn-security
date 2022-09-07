using System;
using System.Collections.Generic;
using System.Threading;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that allows adding any amount of new members to a group in one step.
    /// It is also able to add one group to one or more parent groups in one step.
    /// </summary>
    [Serializable]
    public class AddMembersToGroupActivity : MembershipActivity
    {
        internal int GroupId { get; }
        internal IEnumerable<int> UserMembers { get; }
        internal IEnumerable<int> GroupMembers { get; }
        internal IEnumerable<int> ParentGroups { get; }

        /// <summary>
        /// Initializes a new instance of the AddMembersToGroupActivity.
        /// If any of the given groups is missing, it will be created.
        /// </summary>
        /// <param name="groupId">The group identifier.</param>
        /// <param name="userMembers">Collection of the ids of new user members.</param>
        /// <param name="groupMembers">Collection of the ids of new group members.</param>
        /// <param name="parentGroups">Collection of group ids. The provided group will be a member of these groups.</param>
        public AddMembersToGroupActivity(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, IEnumerable<int> parentGroups)
        {
            GroupId = groupId;
            UserMembers = userMembers;
            GroupMembers = groupMembers;
            ParentGroups = parentGroups;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override void Store(SecurityContext context)
        {
            context.SecuritySystem.DataHandler.AddMembersAsync(GroupId, UserMembers, GroupMembers, ParentGroups,
                CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.Cache.AddMembers(GroupId, GroupMembers, UserMembers, ParentGroups);
        }
    }
}
