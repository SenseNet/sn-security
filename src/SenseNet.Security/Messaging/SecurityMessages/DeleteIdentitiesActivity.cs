using System;
using System.Collections.Generic;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that deletes one or more identities.
    /// </summary>
    [Serializable]
    public class DeleteIdentitiesActivity : MembershipActivity
    {
        internal IEnumerable<int> IdentityIds { get; }

        /// <summary>
        /// Initializes a new instance of the DeleteIdentitiesActivity.
        /// </summary>
        public DeleteIdentitiesActivity(IEnumerable<int> identityIds)
        {
            IdentityIds = identityIds;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override void Store(SecurityContext context)
        {
            context.SecuritySystem.DataHandler.DeleteIdentities(context, IdentityIds);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.Cache.DeleteIdentities(context, IdentityIds);
        }
    }
}
