using System;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that deletes a user.
    /// </summary>
    [Serializable]
    public class DeleteUserActivity : MembershipActivity
    {
        internal int UserId { get; }

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
        protected override void Store(SecurityContext context)
        {
            DataHandler.DeleteUser(context, UserId);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.Cache.DeleteUser(context, UserId);
        }
    }
}
