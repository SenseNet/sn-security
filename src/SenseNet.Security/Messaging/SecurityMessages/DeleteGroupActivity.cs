using System;
using System.Threading;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that deletes a group.
    /// </summary>
    [Serializable]
    public class DeleteGroupActivity : MembershipActivity
    {
        internal int GroupId { get; }

        /// <summary>
        /// Initializes a new instance of the DeleteGroupActivity.
        /// </summary>
        public DeleteGroupActivity(int groupId)
        {
            GroupId = groupId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override void Store(SecurityContext context)
        {
            context.SecuritySystem.DataHandler.DeleteSecurityGroupAsync(GroupId, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.Cache.DeleteSecurityGroup(context, GroupId);
        }
    }
}
