using System;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that deletes a security entity.
    /// </summary>
    [Serializable]
    public class DeleteSecurityEntityActivity : SecurityActivity
    {
        internal int EntityId { get; }

        /// <summary>
        /// Initializes a new instance of the DeleteSecurityEntityActivity.
        /// </summary>
        public DeleteSecurityEntityActivity(int entityId)
        {
            this.EntityId = entityId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override void Store(SecurityContext context)
        {
            DataHandler.DeleteSecurityEntity(context, this.EntityId);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            SecurityEntity.DeleteEntity(context, this.EntityId);
        }

        internal override bool MustWaitFor(SecurityActivity olderActivity)
        {
            if (olderActivity is MembershipActivity)
                return true;

            var createSecurityEntityActivity = olderActivity as CreateSecurityEntityActivity;
            if (createSecurityEntityActivity != null)
            {
                return (createSecurityEntityActivity.EntityId == this.EntityId)
                       || DependencyTools.IsInTree(this.Context, createSecurityEntityActivity.ParentEntityId, this.EntityId);
            }

            var deleteSecurityEntityActivity = olderActivity as DeleteSecurityEntityActivity;
            if (deleteSecurityEntityActivity != null)
            {
                return DependencyTools.HasAncestorRelation(this.Context, this.EntityId, deleteSecurityEntityActivity.EntityId);
            }

            var modifySecurityEntityOwnerActivity = olderActivity as ModifySecurityEntityOwnerActivity;
            if (modifySecurityEntityOwnerActivity != null)
            {
                return DependencyTools.IsInTree(this.Context, modifySecurityEntityOwnerActivity.EntityId, this.EntityId);
            }

            var moveSecurityEntityActivity = olderActivity as MoveSecurityEntityActivity;
            if (moveSecurityEntityActivity != null)
            {
                var ctx = this.Context;
                var entities = SecurityEntity.PeekEntities(ctx, this.EntityId, moveSecurityEntityActivity.SourceId, moveSecurityEntityActivity.TargetId);

                var deleteTarget = entities[0];
                var moveSource = entities[1];
                var moveTarget = entities[2];

                if (DependencyTools.HasAncestorRelation(ctx, moveSource, deleteTarget))
                    return true;
                if (DependencyTools.IsInTree(ctx, moveTarget, this.EntityId))
                    return true;
            }

            var setAclActivity = olderActivity as SetAclActivity;
            if (setAclActivity != null)
                return DependencyTools.AnyIsInTree(this.Context, setAclActivity.AllEntityIds, this.EntityId);

            return false;
        }

    }
}
