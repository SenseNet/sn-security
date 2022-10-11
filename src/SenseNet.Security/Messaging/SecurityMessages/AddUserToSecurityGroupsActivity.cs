using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that allows adding a user to one or more groups in one step.
    /// </summary>
    [Serializable]
    public class AddUserToSecurityGroupsActivity : MembershipActivity
    {
        public int UserId { get; set; }
        public IEnumerable<int> ParentGroups { get; set; }

        internal AddUserToSecurityGroupsActivity() { }

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
        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return context.SecuritySystem.DataHandler.AddUserToGroupsAsync(UserId, ParentGroups, cancel);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.SecuritySystem.Cache.AddUserToGroups(UserId, ParentGroups);
        }
    }
}
