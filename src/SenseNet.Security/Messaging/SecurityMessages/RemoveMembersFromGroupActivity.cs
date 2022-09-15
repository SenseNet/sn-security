﻿using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that removes one or more members from a group in one step.
    /// It can also remove one group from multiple parent groups in one step.
    /// </summary>
    [Serializable]
    public class RemoveMembersFromGroupActivity : MembershipActivity
    {
        internal int GroupId { get; }
        internal IEnumerable<int> UserMembers { get; }
        internal IEnumerable<int> GroupMembers { get; }
        internal IEnumerable<int> ParentGroups { get; }

        /// <summary>
        /// Initializes a new instance of the RemoveMembersFromGroupActivity.
        /// </summary>
        public RemoveMembersFromGroupActivity(int groupId, IEnumerable<int> userMembers, IEnumerable<int> groupMembers, IEnumerable<int> parentGroups)
        {
            GroupId = groupId;
            UserMembers = userMembers;
            GroupMembers = groupMembers;
            ParentGroups = parentGroups;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return context.SecuritySystem.DataHandler.RemoveMembersAsync(GroupId, UserMembers, GroupMembers, ParentGroups, cancel);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.Cache.RemoveMembers(GroupId, GroupMembers, UserMembers, ParentGroups);
        }
    }
}
