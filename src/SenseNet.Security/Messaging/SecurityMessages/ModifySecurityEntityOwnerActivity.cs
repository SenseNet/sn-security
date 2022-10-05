using System;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that updates the owner of an entity.
    /// </summary>
    [Serializable]
    public class ModifySecurityEntityOwnerActivity : SecurityActivity
    {
        public int EntityId { get; set; }
        public int OwnerId { get; set; }

        internal ModifySecurityEntityOwnerActivity() { }

        /// <summary>
        /// Initializes a new instance of the ModifySecurityEntityOwnerActivity.
        /// </summary>
        public ModifySecurityEntityOwnerActivity(int entityId, int ownerId)
        {
            EntityId = entityId;
            OwnerId = ownerId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return context.SecuritySystem.DataHandler.ModifySecurityEntityOwnerAsync(EntityId, OwnerId, cancel);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.SecuritySystem.EntityManager.ModifyEntityOwner(EntityId, OwnerId);
        }

        internal override bool MustWaitFor(SecurityActivity olderActivity)
        {
            if (olderActivity is MembershipActivity)
                return true;

            // There aren't any valid scenarios if the olderActivity is DeleteSecurityEntityActivity, MoveSecurityEntityActivity or SetAclActivity

            if (olderActivity is CreateSecurityEntityActivity createSecurityEntityActivity)
            {
                return createSecurityEntityActivity.EntityId == EntityId;
            }

            var modifySecurityEntityOwnerActivity = olderActivity as ModifySecurityEntityOwnerActivity;
            return modifySecurityEntityOwnerActivity?.EntityId == EntityId;
        }
    }
}
