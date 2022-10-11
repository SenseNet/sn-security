using System;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that deletes a user.
    /// </summary>
    [Serializable]
    public class DeleteUserActivity : MembershipActivity
    {
        public int UserId { get; set; }

        internal DeleteUserActivity() { }

        /// <summary>
        /// Initializes a new instance of the DeleteUserActivity.
        /// </summary>
        public DeleteUserActivity(int userId)
        {
            UserId = userId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return context.SecuritySystem.DataHandler.DeleteUserAsync(UserId, cancel);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.SecuritySystem.Cache.DeleteUser(context, UserId);
        }
    }
}
