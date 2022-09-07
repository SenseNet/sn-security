using System;
using System.Collections.Generic;
using System.Threading;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that removes a user from one or more groups.
    /// </summary>
    [Serializable]
    public class RemoveUserFromSecurityGroupsActivity : MembershipActivity
    {
        internal int UserId { get; }
        internal IEnumerable<int> ParentGroups { get; }

        /// <summary>
        /// Initializes a new instance of the RemoveUserFromSecurityGroupsActivity.
        /// </summary>
        public RemoveUserFromSecurityGroupsActivity(int userId, IEnumerable<int> parentGroups)
        {
            UserId = userId;
            ParentGroups = parentGroups;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override void Store(SecurityContext context)
        {
            context.SecuritySystem.DataHandler.RemoveUserFromGroupsAsync(UserId, ParentGroups, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.Cache.RemoveUserFromGroups(UserId, ParentGroups);
        }
    }
}
