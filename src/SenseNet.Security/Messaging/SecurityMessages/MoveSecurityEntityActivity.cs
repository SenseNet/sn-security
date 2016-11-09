using System;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that moves an entity to another location in the entity tree.
    /// </summary>
    [Serializable]
    public class MoveSecurityEntityActivity : SecurityActivity
    {
        internal int SourceId { get; }
        internal int TargetId { get; }

        /// <summary>
        /// Initializes a new instance of the MoveSecurityEntityActivity.
        /// </summary>
        public MoveSecurityEntityActivity(int sourceId, int targetId)
        {
            this.SourceId = sourceId;
            this.TargetId = targetId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override void Store(SecurityContext context)
        {
            DataHandler.MoveSecurityEntity(context, this.SourceId, this.TargetId);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            SecurityEntity.MoveEntity(context, this.SourceId, this.TargetId);
        }

        internal override bool MustWaitFor(SecurityActivity olderActivity)
        {
            if (olderActivity is MembershipActivity)
                return true;

            // There aren't any valid scenarios if the olderActivity is ModifySecurityEntityOwnerActivity or SetAclActivity

            var createSecurityEntityActivity = olderActivity as CreateSecurityEntityActivity;
            if (createSecurityEntityActivity != null)
                return (this.SourceId == createSecurityEntityActivity.EntityId) || (this.TargetId == createSecurityEntityActivity.EntityId);

            var deleteSecurityEntityActivity = olderActivity as DeleteSecurityEntityActivity;
            if (deleteSecurityEntityActivity != null)
            {
                var ctx = this.Context;
                var entities = SecurityEntity.PeekEntities(ctx, deleteSecurityEntityActivity.EntityId, this.SourceId, this.TargetId);

                var deleteTarget = entities[0];
                var moveSource = entities[1];
                var moveTarget = entities[2];

                if (DependencyTools.HasAncestorRelation(ctx, moveSource, deleteTarget))
                    return true;
                if (DependencyTools.HasAncestorRelation(ctx, moveTarget, deleteTarget))
                    return true;
            }
            var moveSecurityEntityActivity = olderActivity as MoveSecurityEntityActivity;
            if (moveSecurityEntityActivity != null)
            {
                var ctx = this.Context;
                var entities = SecurityEntity.PeekEntities(ctx, this.SourceId, this.TargetId, moveSecurityEntityActivity.SourceId, moveSecurityEntityActivity.TargetId);
                var move1Source = entities[0];
                var move1Target = entities[1];
                var move2Source = entities[2];
                var move2Target = entities[3];

                if (
                    DependencyTools.HasAncestorRelation(ctx, move1Source, move2Source) ||
                    DependencyTools.HasAncestorRelation(ctx, move1Source, move2Target) ||
                    DependencyTools.HasAncestorRelation(ctx, move1Target, move2Source) ||
                    DependencyTools.HasAncestorRelation(ctx, move1Target, move2Target)
                    )
                    return true;
            }
            return false;
        }
    }
}
