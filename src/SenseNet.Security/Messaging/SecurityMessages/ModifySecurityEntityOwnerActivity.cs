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
            this.EntityId = entityId;
            this.OwnerId = ownerId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override void Store(SecurityContext context)
        {
            DataHandler.ModifySecurityEntityOwner(context, this.EntityId, this.OwnerId);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            SecurityEntity.ModifyEntityOwner(context, this.EntityId, this.OwnerId);
        }

        internal override bool MustWaitFor(SecurityActivity olderActivity)
        {
            if (olderActivity is MembershipActivity)
                return true;

            // There aren't any valid scenarios if the olderActivity is DeleteSecurityEntityActivity, MoveSecurityEntityActivity or SetAclActivity

            var createSecurityEntityActivity = olderActivity as CreateSecurityEntityActivity;
            if (createSecurityEntityActivity != null)
            {
                return createSecurityEntityActivity.EntityId == this.EntityId;
            }

            var modifySecurityEntityOwnerActivity = olderActivity as ModifySecurityEntityOwnerActivity;
            return modifySecurityEntityOwnerActivity?.EntityId == EntityId;
        }
    }
}
