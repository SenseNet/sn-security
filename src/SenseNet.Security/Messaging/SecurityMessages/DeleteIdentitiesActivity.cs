using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that deletes one or more identities.
    /// </summary>
    [Serializable]
    public class DeleteIdentitiesActivity : MembershipActivity
    {
        public IEnumerable<int> IdentityIds { get; set; }

        internal DeleteIdentitiesActivity() { }

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
        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return context.SecuritySystem.DataHandler.DeleteIdentitiesAsync(IdentityIds, cancel);
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
