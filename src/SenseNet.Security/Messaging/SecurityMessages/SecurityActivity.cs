using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading;
using System.Linq;
using SenseNet.Diagnostics;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Base class of all security related activities.
    /// </summary>
    [Serializable]
    public abstract class SecurityActivity : DistributedMessage, IDeserializationCallback
    {
        // ---------------------- hierarchy
        // MembershipActivity
        //     AddUserToSecurityGroupsActivity: UserId, ParentGroups
        //     RemoveUserFromSecurityGroupsActivity: UserId, ParentGroups
        //     AddMembersToGroupActivity: GroupId, UserMembers, GroupMembers, ParentGroups
        //     RemoveMembersFromGroupActivity: GroupId, UserMembers, GroupMembers, ParentGroups
        //     DeleteUserActivity: UserId
        //     DeleteGroupActivity: GroupId
        //     DeleteIdentitiesActivity: IdentityIds
        // CreateSecurityEntityActivity: EntityId, ParentEntityId
        // DeleteSecurityEntityActivity: EntityId
        // ModifySecurityEntityOwnerActivity: EntityId
        // MoveSecurityEntityActivity: SourceId, TargetId
        // SetAclActivity: _acls, _entries, _entriesToRemove, _breaks, _unbreaks

        private Exception _executionException;

        [NonSerialized] private SecurityContext __context;
        /// <summary>
        /// Gets the current SecurityContext.
        /// </summary>
        public SecurityContext Context { get => __context; internal set => __context = value; }

        /// <summary>
        /// Initializes the instance.
        /// Sets the TypeName property to the name of the .Net type of this instance;
        /// </summary>
        protected SecurityActivity()
        {
            TypeName = GetType().Name;
        }

        /// <summary>
        /// Executes the activity by adding it to the activity queue.
        /// </summary>
        /// <param name="context">Current SecurityContext</param>
        /// <param name="waitForComplete">If the value is true (default),
        /// the current thread waits for the full execution on this computer.
        /// Otherwise the method returns immediately.</param>
        public void Execute(SecurityContext context, bool waitForComplete = true) //UNDONE:x: async-await?
        {
            Context = context;
            if (Sender == null)
                Sender = context.SecuritySystem.MessageSenderManager.CreateMessageSender();

            context.SecuritySystem.SecurityActivityQueue.ExecuteActivityAsync(this)
                .ConfigureAwait(false).GetAwaiter().GetResult();

            if(waitForComplete)
                WaitForComplete();

            if (_executionException != null)
                throw _executionException;
        }

        /// <summary>
        /// Called by an internal component in right order.
        /// </summary>
        //UNDONE:x: Async SecurityActivity.ExecuteInternal (call abstract methods)
        internal void ExecuteInternal()
        {
            try
            {
                using (var execLock = Context.SecuritySystem.DataHandler
                           .AcquireSecurityActivityExecutionLockAsync(this, CancellationToken.None)
                           .ConfigureAwait(false).GetAwaiter().GetResult())
                {
                    if (execLock.FullExecutionEnabled)
                    {
                        Initialize(Context);
                        Store(Context);
                        Distribute(Context);
                    }
                }
                Apply(Context);
            }
            catch (Exception e)
            {
                _executionException = e;

                // we log this here, because if the activity is not waited for later than the exception would not be logged
                SnTrace.Security.WriteError("Error during security activity execution. SA{0} {1}", Id, e);
            }
            finally
            {
                Finish();
            }
        }


        /// <summary>
        /// Extension point for initializing the activity data before executing any operations.
        /// </summary>
        /// <param name="context">Current SecurityContext to use any security related thing.</param>
        protected virtual void Initialize(SecurityContext context)
        {
            // default implementation does nothing
        }
        private void Distribute(SecurityContext context) //UNDONE:x: async-await?
        {
            DistributedMessage msg = this;
            if (BodySize > __context.SecuritySystem.MessagingOptions.DistributableSecurityActivityMaxSize)
                msg = new BigActivityMessage { DatabaseId = Id };
            context.SecuritySystem.MessageProvider.SendMessage(msg);
        }

        //UNDONE:x: Async SecurityActivity.Store (abstract)
        /// <summary>
        /// Customization point for the activity data persistence.
        /// </summary>
        /// <param name="context">Current SecurityContext to use any security related thing.</param>
        protected abstract void Store(SecurityContext context);

        /// <summary>
        /// Customization point for the memory operations based on the activity data.
        /// </summary>
        /// <param name="context">Current SecurityContext to use any security related thing.</param>
        protected abstract void Apply(SecurityContext context);

        internal abstract bool MustWaitFor(SecurityActivity olderActivity);

        [NonSerialized]
        private readonly AutoResetEvent _finishSignal = new AutoResetEvent(false);
        [NonSerialized]
        private bool _finished;

        internal void WaitForComplete()
        {
            if (_finished)
                return;

            if (_finishSignal == null)
                return;

            if (Debugger.IsAttached)
            {
                _finishSignal.WaitOne();
            }
            else
            {
                if (!_finishSignal.WaitOne(__context.SecuritySystem.MessagingOptions.SecurityActivityTimeoutInSeconds * 1000, false))
                {
                    var message = $"SecurityActivity is not finishing on a timely manner (#{Id})";
                    throw new SecurityActivityTimeoutException(message);
                }
            }
        }

        [NonSerialized]
        private SecurityActivity _attachedActivity;
        internal SecurityActivity AttachedActivity
        {
            get => _attachedActivity;
            private set => _attachedActivity = value;
        }

        /// <summary>
        /// When an activity gets executed and needs to be finalized, all activity objects that have
        /// the same id need to be finalized too. The Attach methods puts all activities with the
        /// same id to a chain to let the Finish method call the Finish method of each object in the chain.
        /// This method was needed because it is possible that the same activity arrives from different
        /// sources: e.g from messaging, from database or from direct execution.
        /// </summary>
        /// <param name="activity"></param>
        internal void Attach(SecurityActivity activity)
        {
            if (ReferenceEquals(this, activity))
                return;
            if (AttachedActivity == null)
                AttachedActivity = activity;
            else
                AttachedActivity.Attach(activity);
        }

        /// <summary>
        /// Finish the full activity chain (see the Attach method for details).
        /// </summary>
        internal void Finish()
        {
            _finished = true;
            // finalize attached activities first
            AttachedActivity?.Finish();
            _finishSignal?.Set();
        }

        internal static class DependencyTools
        {
            internal static bool HasAncestorRelation(SecurityContext ctx, int entityId1, int entityId2)
            {
                var entities = ctx.SecuritySystem.EntityManager.PeekEntities(entityId1, entityId2);
                return HasAncestorRelation(ctx, entities[0], entities[1]);
            }
            internal static bool HasAncestorRelation(SecurityContext ctx, SecurityEntity entity1, SecurityEntity entity2)
            {
                if (entity1 == null || entity2 == null)
                    return false;
                return ctx.IsEntityInTree(entity2, entity1.Id)
                    || ctx.IsEntityInTree(entity1, entity2.Id);
            }

            internal static bool IsInTree(SecurityContext ctx, int descendantId, int ancestorId)
            {
                var entities = ctx.SecuritySystem.EntityManager.PeekEntities(descendantId);
                return IsInTree(ctx, entities[0], ancestorId);
            }
            internal static bool IsInTree(SecurityContext ctx, SecurityEntity descendant, int ancestorId)
            {
                return ctx.IsEntityInTree(descendant, ancestorId);
            }

            internal static bool AnyIsInTree(SecurityContext ctx, IEnumerable<int> descendantIds, int ancestorId)
            {
                var entities = ctx.SecuritySystem.EntityManager.PeekEntities(descendantIds.ToArray());
                return entities.Any(entity => ctx.IsEntityInTree(entity, ancestorId));
            }
        }

        //  -   -   -   -   -   -   -   -   -   -   -   -   -   -   -   -   -   -   refactored

        /// <summary>
        /// Database id of the activity instance
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Name of the activity type.
        /// </summary>
        public string TypeName { get; private set; }


        [NonSerialized]
        private bool _fromReceiver;
        /// <summary>
        /// Gets or sets whether the activity comes from the message receiver.
        /// </summary>
        public bool FromReceiver
        {
            get => _fromReceiver;
            set => _fromReceiver = value;
        }

        [NonSerialized]
        private bool _fromDatabase;
        /// <summary>
        /// Gets or sets whether the activity is loaded from the database.
        /// </summary>
        public bool FromDatabase
        {
            get => _fromDatabase;
            set => _fromDatabase = value;
        }

        [NonSerialized]
        private bool _isUnprocessedActivity;
        /// <summary>
        /// Gets or sets whether the activity is loaded from the database at the system start.
        /// </summary>
        public bool IsUnprocessedActivity
        {
            get => _isUnprocessedActivity;
            set => _isUnprocessedActivity = value;
        }

        [field: NonSerialized]
        internal List<SecurityActivity> WaitingFor { get; private set; } = new List<SecurityActivity>();

        [field: NonSerialized]
        internal List<SecurityActivity> WaitingForMe { get; private set; } = new List<SecurityActivity>();

        internal void WaitFor(SecurityActivity olderActivity)
        {
            // this method must called from thread safe block.
            if (WaitingFor.All(x => x.Id != olderActivity.Id))
                WaitingFor.Add(olderActivity);
            if (olderActivity.WaitingForMe.All(x => x.Id != Id))
                olderActivity.WaitingForMe.Add(this);
        }

        internal void FinishWaiting(SecurityActivity olderActivity)
        {
            // this method must called from thread safe block.
            RemoveDependency(WaitingFor, olderActivity);
            RemoveDependency(olderActivity.WaitingForMe, this);
        }
        private void RemoveDependency(List<SecurityActivity> dependencyList, SecurityActivity activity)
        {
            // this method must called from thread safe block.
            dependencyList.RemoveAll(x => x.Id == activity.Id);
        }

        /// <summary>
        /// Runs when the entire object graph has been deserialized.
        /// Called by the .NET framework.
        /// </summary>
        public void OnDeserialization(object sender)
        {
            WaitingFor = new List<SecurityActivity>();
            WaitingForMe = new List<SecurityActivity>();
        }
    }
}
