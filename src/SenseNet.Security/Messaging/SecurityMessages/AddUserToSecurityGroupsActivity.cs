using System;
using System.Collections.Generic;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that allows adding a user to one or more groups in one step.
    /// </summary>
    [Serializable]
    public class AddUserToSecurityGroupsActivity : MembershipActivity
    {
        internal int UserId { get; }
        internal IEnumerable<int> ParentGroups { get; }

        /// <summary>
        /// Initializes a new instance of the AddMembersToGroupActivity.
        /// </summary>
        /// <param name="userId">Id of the user.</param>
        /// <param name="parentGroups">Group ids that will be parent of this user.</param>
        public AddUserToSecurityGroupsActivity(int userId, IEnumerable<int> parentGroups)
        {
            UserId = userId;
            ParentGroups = parentGroups;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override void Store(SecurityContext context)
        {
            SecuritySystem.Instance.DataHandler.AddUserToGroups(context, UserId, ParentGroups);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.Cache.AddUserToGroups(UserId, ParentGroups);
        }
    }
}
