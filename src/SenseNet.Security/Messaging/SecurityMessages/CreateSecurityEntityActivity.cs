using System;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that creates a security entity.
    /// </summary>
    [Serializable]
    public class CreateSecurityEntityActivity : SecurityActivity
    {
        public int EntityId { get; set; }
        public int ParentEntityId { get; set; }
        public int OwnerId { get; set; }

        internal CreateSecurityEntityActivity() { }

        /// <summary>
        /// Initializes a new instance of the CreateSecurityEntityActivity.
        /// </summary>
        public CreateSecurityEntityActivity(int entityId, int parentEntityId, int ownerId)
        {
            EntityId = entityId;
            ParentEntityId = parentEntityId;
            OwnerId = ownerId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return context.SecuritySystem.DataHandler.CreateSecurityEntityAsync(EntityId, ParentEntityId, OwnerId, cancel);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.SecuritySystem.EntityManager.CreateEntity(EntityId, ParentEntityId, OwnerId);
        }

        internal override bool ShouldWaitFor(SecurityActivity olderActivity)
        {
            if (olderActivity is MembershipActivity)
                return true;

            // There aren't any valid scenarios if the olderActivity is ModifySecurityEntityOwnerActivity or SetAclActivity

            if (olderActivity is CreateSecurityEntityActivity createSecurityEntityActivity)
                return createSecurityEntityActivity.EntityId == ParentEntityId;

            if (olderActivity is DeleteSecurityEntityActivity deleteSecurityEntityActivity)
                return deleteSecurityEntityActivity.EntityId == EntityId
                    || DependencyTools.IsInTree(Context, ParentEntityId, deleteSecurityEntityActivity.EntityId);

            if (olderActivity is MoveSecurityEntityActivity moveSecurityEntityActivity)
                return moveSecurityEntityActivity.SourceId == EntityId || moveSecurityEntityActivity.TargetId == EntityId;

            return false;
        }
    }
}
