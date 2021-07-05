using System;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that updates the owner of an entity.
    /// </summary>
    [Serializable]
    public class ModifySecurityEntityOwnerActivity : SecurityActivity
    {
        internal int EntityId { get; }
        internal int OwnerId { get; }

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
        protected override void Store(SecurityContext context)
        {
            SecuritySystem.Instance.DataHandler.ModifySecurityEntityOwner(context, EntityId, OwnerId);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            SecurityEntity.ModifyEntityOwner(context, EntityId, OwnerId);
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
