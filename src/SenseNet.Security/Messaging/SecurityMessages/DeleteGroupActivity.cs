using System;

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
            this.GroupId = groupId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override void Store(SecurityContext context)
        {
            DataHandler.DeleteSecurityGroup(context, GroupId);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.Cache.DeleteSecurityGroup(context, this.GroupId);
        }
    }
}
