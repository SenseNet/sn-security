﻿using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that removes a user from one or more groups.
    /// </summary>
    [Serializable]
    public class RemoveUserFromSecurityGroupsActivity : MembershipActivity
    {
        public int UserId { get; set; }
        public IEnumerable<int> ParentGroups { get; set; }

        internal RemoveUserFromSecurityGroupsActivity() { }

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
        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return context.SecuritySystem.DataHandler.RemoveUserFromGroupsAsync(UserId, ParentGroups, cancel);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.SecuritySystem.Cache.RemoveUserFromGroups(UserId, ParentGroups);
        }
    }
}
