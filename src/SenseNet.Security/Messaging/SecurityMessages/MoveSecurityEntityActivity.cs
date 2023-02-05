using System;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that moves an entity to another location in the entity tree.
    /// </summary>
    [Serializable]
    public class MoveSecurityEntityActivity : SecurityActivity
    {
        public int SourceId { get; set; }
        public int TargetId { get; set; }

        internal MoveSecurityEntityActivity() { }

        /// <summary>
        /// Initializes a new instance of the MoveSecurityEntityActivity.
        /// </summary>
        public MoveSecurityEntityActivity(int sourceId, int targetId)
        {
            SourceId = sourceId;
            TargetId = targetId;
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return context.SecuritySystem.DataHandler.MoveSecurityEntityAsync(SourceId, TargetId, cancel);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            context.SecuritySystem.EntityManager.MoveEntity(SourceId, TargetId);
        }

        internal override bool ShouldWaitFor(SecurityActivity olderActivity)
        {
            if (olderActivity is MembershipActivity)
                return true;

            // There aren't any valid scenarios if the olderActivity is ModifySecurityEntityOwnerActivity or SetAclActivity

            if (olderActivity is CreateSecurityEntityActivity createSecurityEntityActivity)
                return SourceId == createSecurityEntityActivity.EntityId || TargetId == createSecurityEntityActivity.EntityId;

            if (olderActivity is DeleteSecurityEntityActivity deleteSecurityEntityActivity)
            {
                var ctx = Context;
                var entities = ctx.SecuritySystem.EntityManager.PeekEntities(deleteSecurityEntityActivity.EntityId, SourceId, TargetId);

                var deleteTarget = entities[0];
                var moveSource = entities[1];
                var moveTarget = entities[2];

                if (DependencyTools.HasAncestorRelation(ctx, moveSource, deleteTarget))
                    return true;
                if (DependencyTools.HasAncestorRelation(ctx, moveTarget, deleteTarget))
                    return true;
            }

            if (olderActivity is MoveSecurityEntityActivity moveSecurityEntityActivity)
            {
                var ctx = Context;
                var entities = ctx.SecuritySystem.EntityManager.PeekEntities(SourceId, TargetId, moveSecurityEntityActivity.SourceId, moveSecurityEntityActivity.TargetId);
                var move1Source = entities[0];
                var move1Target = entities[1];
                var move2Source = entities[2];
                var move2Target = entities[3];

                if (
                    DependencyTools.HasAncestorRelation(ctx, move1Source, move2Source) ||
                    DependencyTools.HasAncestorRelation(ctx, move1Source, move2Target) ||
                    DependencyTools.HasAncestorRelation(ctx, move1Target, move2Source) ||
                    DependencyTools.HasAncestorRelation(ctx, move1Target, move2Target))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
