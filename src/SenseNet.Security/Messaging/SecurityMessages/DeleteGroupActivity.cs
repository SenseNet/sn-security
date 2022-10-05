using System;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that deletes a group.
    /// </summary>
    [Serializable]
    public class DeleteGroupActivity : MembershipActivity
    {
        public int GroupId { get; set; }

        public DeleteGroupActivity() { }

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
        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return context.SecuritySystem.DataHandler.DeleteSecurityGroupAsync(GroupId, cancel);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.SecuritySystem.Cache.DeleteSecurityGroup(context, GroupId);
        }
    }
}
