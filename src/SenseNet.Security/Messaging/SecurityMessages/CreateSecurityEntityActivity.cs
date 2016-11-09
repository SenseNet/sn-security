using System;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that creates a security entity.
    /// </summary>
    [Serializable]
    public class CreateSecurityEntityActivity : SecurityActivity
    {
        internal int EntityId { get; }
        internal int ParentEntityId { get; }
        internal int OwnerId { get; }

        /// <summary>
        /// Initializes a new instance of the CreateSecurityEntityActivity.
        /// </summary>
        public CreateSecurityEntityActivity(int entityId, int parentEntityId, int ownerId)
        {
            this.EntityId = entityId;
            this.ParentEntityId = parentEntityId;
            this.OwnerId = ownerId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override void Store(SecurityContext context)
        {
            DataHandler.CreateSecurityEntity(context, this.EntityId, this.ParentEntityId, this.OwnerId);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            SecurityEntity.CreateEntity(context, this.EntityId, this.ParentEntityId, this.OwnerId);
        }

        internal override bool MustWaitFor(SecurityActivity olderActivity)
        {
            if (olderActivity is MembershipActivity)
                return true;

            // There aren't any valid scenarios if the olderActivity is ModifySecurityEntityOwnerActivity or SetAclActivity

            var createSecurityEntityActivity = olderActivity as CreateSecurityEntityActivity;
            if (createSecurityEntityActivity != null)
                return createSecurityEntityActivity.EntityId == this.ParentEntityId;

            var deleteSecurityEntityActivity = olderActivity as DeleteSecurityEntityActivity;
            if (deleteSecurityEntityActivity != null)
                return deleteSecurityEntityActivity.EntityId == this.EntityId
                    || DependencyTools.IsInTree(this.Context, this.ParentEntityId, deleteSecurityEntityActivity.EntityId);

            var moveSecurityEntityActivity = olderActivity as MoveSecurityEntityActivity;
            if (moveSecurityEntityActivity != null)
                return (moveSecurityEntityActivity.SourceId == this.EntityId) || (moveSecurityEntityActivity.TargetId == this.EntityId);

            return false;
        }
    }
}
