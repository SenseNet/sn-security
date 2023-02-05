using System;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that deletes a security entity.
    /// </summary>
    [Serializable]
    public class DeleteSecurityEntityActivity : SecurityActivity
    {
        public int EntityId { get; set; }

        internal DeleteSecurityEntityActivity() { }

        /// <summary>
        /// Initializes a new instance of the DeleteSecurityEntityActivity.
        /// </summary>
        public DeleteSecurityEntityActivity(int entityId)
        {
            EntityId = entityId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return context.SecuritySystem.DataHandler.DeleteSecurityEntityAsync(EntityId, cancel);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.SecuritySystem.EntityManager.DeleteEntity(EntityId);
        }

        internal override bool ShouldWaitFor(SecurityActivity olderActivity)
        {
            if (olderActivity is MembershipActivity)
                return true;

            if (olderActivity is CreateSecurityEntityActivity createSecurityEntityActivity)
            {
                return createSecurityEntityActivity.EntityId == EntityId
                       || DependencyTools.IsInTree(Context, createSecurityEntityActivity.ParentEntityId, EntityId);
            }

            if (olderActivity is DeleteSecurityEntityActivity deleteSecurityEntityActivity)
            {
                return DependencyTools.HasAncestorRelation(Context, EntityId, deleteSecurityEntityActivity.EntityId);
            }

            if (olderActivity is ModifySecurityEntityOwnerActivity modifySecurityEntityOwnerActivity)
            {
                return DependencyTools.IsInTree(Context, modifySecurityEntityOwnerActivity.EntityId, EntityId);
            }

            if (olderActivity is MoveSecurityEntityActivity moveSecurityEntityActivity)
            {
                var ctx = Context;
                var entities = ctx.SecuritySystem.EntityManager.PeekEntities(EntityId, moveSecurityEntityActivity.SourceId, moveSecurityEntityActivity.TargetId);

                var deleteTarget = entities[0];
                var moveSource = entities[1];
                var moveTarget = entities[2];

                if (DependencyTools.HasAncestorRelation(ctx, moveSource, deleteTarget))
                    return true;
                if (DependencyTools.IsInTree(ctx, moveTarget, EntityId))
                    return true;
            }

            if (olderActivity is SetAclActivity setAclActivity)
                return DependencyTools.AnyIsInTree(Context, setAclActivity.AllEntityIds, EntityId);

            return false;
        }

    }
}
