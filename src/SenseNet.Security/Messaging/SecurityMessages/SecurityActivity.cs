using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Serialization;
using System.Threading;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
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

        [field: NonSerialized]
        [JsonIgnore]
        private static int _activityId;

        [field: NonSerialized]
        private int _instanceId;
        [JsonIgnore] internal string Key => $"{Id}-{_instanceId}";

        [field: NonSerialized]
        [JsonIgnore]
        public Exception ExecutionException { get; private set; }

        /// <summary>
        /// Gets the current SecurityContext.
        /// </summary>
        [field: NonSerialized]
        [JsonIgnore]
        public SecurityContext Context { get; internal set; }

        /// <summary>
        /// Initializes the instance.
        /// Sets the TypeName property to the name of the .Net type of this instance;
        /// </summary>
        protected SecurityActivity()
        {
            _instanceId = Interlocked.Increment(ref _activityId);
            TypeName = GetType().Name;
        }

        /// <summary>
        /// Executes the activity by adding it to the activity queue.
        /// </summary>
        /// <param name="context">Current SecurityContext</param>
        /// <param name="waitForComplete">If the value is true (default),
        /// the current thread waits for the full execution on this computer.
        /// Otherwise the method returns immediately.</param>
        [Obsolete("SAQ: Use ExecuteAsync instead.", false)]
        public void Execute(SecurityContext context, bool waitForComplete = true)
        {
            if (context.SecuritySystem.SecurityActivityQueue is SecurityActivityQueue)
            {
                var task = ExecuteAsync(context, CancellationToken.None);
                if(waitForComplete)
                    task.GetAwaiter().GetResult();
                return;
            }

            Context = context;
            if (Sender == null)
                Sender = context.SecuritySystem.MessageSenderManager.CreateMessageSender();

            context.SecuritySystem.SecurityActivityQueue.ExecuteActivity(this);

            if (waitForComplete)
                WaitForComplete();

            if (ExecutionException != null)
                throw ExecutionException;
        }

        /// <summary>
        /// Executes the activity by adding it to the activity queue.
        /// </summary>
        /// <param name="context">Current SecurityContext</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>
        /// A Task that represents the asynchronous operation and wraps the query result.
        /// </returns>
        public async Task ExecuteAsync(SecurityContext context, CancellationToken cancel)
        {
            Context = context;
            Sender ??= context.SecuritySystem.MessageSenderManager.CreateMessageSender();

            var caller = FromReceiver || FromDatabase ? "System" : "Business";
            using var op = SnTrace.SecurityQueue.StartOperation(() => $"App: {caller} executes #SA{this.Key}");
            await context.SecuritySystem.SecurityActivityQueue.ExecuteActivityAsync(this, cancel);
            if (ExecutionException != null)
                throw ExecutionException;
            op.Successful = true;
        }

        /// <summary>
        /// Called by an internal component in right order.
        /// </summary>
        [Obsolete("SAQ: Use ExecuteInternalAsync instead.", false)]
        internal void ExecuteInternal()
        {
            try
            {
                using (var execLock = Context.SecuritySystem.DataHandler
                           .AcquireSecurityActivityExecutionLockAsync(this, CancellationToken.None).GetAwaiter().GetResult())
                {
                    if (execLock.FullExecutionEnabled)
                    {
                        Initialize(Context);
                        StoreAsync(Context, CancellationToken.None).GetAwaiter().GetResult();
                        Distribute(Context);
                    }
                }
                Apply(Context);
            }
            catch (Exception e)
            {
                ExecutionException = e;

                // we log this here, because if the activity is not waited for later than the exception would not be logged
                SnTrace.Security.WriteError("Error during security activity execution. SA{0} {1}", Id, e);
            }
            finally
            {
                Finish();
            }
        }
        internal async Task ExecuteInternalAsync(CancellationToken cancel)
        {
            try
            {
                using var op = SnTrace.SecurityQueue.StartOperation(() => $"SA: ExecuteInternal #SA{Key}");
                using (var execLock = await Context.SecuritySystem.DataHandler
                           .AcquireSecurityActivityExecutionLockAsync(this, CancellationToken.None).ConfigureAwait(false))
                {
                    if (execLock.FullExecutionEnabled)
                    {
                        Initialize(Context);
                        await StoreAsync(Context, CancellationToken.None).ConfigureAwait(false);
                        Distribute(Context);
                    }
                }
                Apply(Context);
                op.Successful = true;
            }
            catch (TaskCanceledException)
            {
                SnTrace.Security.Write(() => $"A security activity execution CANCELED. #SA{Key}");
            }
            catch (Exception e)
            {
                ExecutionException = e;

                // we log this here, because if the activity is not waited for later than the exception would not be logged
                SnTrace.Security.WriteError(() => $"Error during security activity execution. #SA{Key} {e}");
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
        private void Distribute(SecurityContext context)
        {
            DistributedMessage msg = this;
            if (BodySize > Context.SecuritySystem.MessagingOptions.DistributableSecurityActivityMaxSize)
                msg = new BigActivityMessage { DatabaseId = Id };
            context.SecuritySystem.MessageProvider.SendMessage(msg);
        }

        /// <summary>
        /// Customization point for the activity data persistence.
        /// </summary>
        /// <param name="context">Current SecurityContext to use any security related thing.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        protected abstract Task StoreAsync(SecurityContext context, CancellationToken cancel);
        /// <summary>
        /// Customization point for the memory operations based on the activity data.
        /// </summary>
        /// <param name="context">Current SecurityContext to use any security related thing.</param>
        protected abstract void Apply(SecurityContext context);

        internal abstract bool ShouldWaitFor(SecurityActivity olderActivity);

        [NonSerialized]
        private readonly AutoResetEvent _finishSignal = new AutoResetEvent(false);
        [NonSerialized]
        private bool _finished;
        [NonSerialized]
        private int _waitingThreadId;

        internal void WaitForComplete()
        {
            if (_finished)
                return;

            if (_finishSignal == null)
                return;

            _waitingThreadId = Thread.CurrentThread.ManagedThreadId;
            SnTrace.SecurityQueue.Write("SAQ: activity blocks the T{1}: SA{0}", Id, _waitingThreadId);

            if (Debugger.IsAttached)
            {
                _finishSignal.WaitOne();
            }
            else
            {
                if (!_finishSignal.WaitOne(Context.SecuritySystem.MessagingOptions.SecurityActivityTimeoutInSeconds * 1000, false))
                {
                    var message = $"SecurityActivity is not finishing on a timely manner (#{Id})";
                    throw new SecurityActivityTimeoutException(message);
                }
            }
        }

        /// <summary>
        /// Finish the full activity chain (see the Attach method for details).
        /// </summary>
        internal void Finish()
        {
            _finished = true;

            // finalize attached activities first
            foreach (var attachment in _attachments)
                attachment.Finish();

            if (_finishSignal != null)
            {
                _finishSignal.Set();
                if (_waitingThreadId > 0)
                    SnTrace.SecurityQueue.Write("SAQ: waiting resource released T{0}.", _waitingThreadId);
            }
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


        /// <summary>
        /// Gets or sets whether the activity comes from the message receiver.
        /// </summary>
        [field: NonSerialized]
        [JsonIgnore]
        public bool FromReceiver { get; set; }

        /// <summary>
        /// Gets or sets whether the activity is loaded from the database.
        /// </summary>
        [field: NonSerialized]
        [JsonIgnore]
        public bool FromDatabase { get; set; }

        /// <summary>
        /// Gets or sets whether the activity is loaded from the database at the system start.
        /// </summary>
        [field: NonSerialized]
        [JsonIgnore]
        public bool IsUnprocessedActivity { get; set; }

        [field: NonSerialized]
        [JsonIgnore]
        internal List<SecurityActivity> WaitingFor { get; private set; } = new();

        [field: NonSerialized]
        [JsonIgnore]
        internal List<SecurityActivity> WaitingForMe { get; private set; } = new();

        internal void WaitFor(SecurityActivity olderActivity)
        {
            SnTrace.SecurityQueue.Write(() => $"SA: Make dependency: #SA{Key} depends from SA{olderActivity.Key}.");
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



        [field: NonSerialized]
        [JsonIgnore]
        internal CancellationToken CancellationToken { get; set; }

        [field: NonSerialized]
        [JsonIgnore]
        private Task _executionTask;
        [field: NonSerialized]
        [JsonIgnore]
        private Task _finalizationTask;

        internal Task CreateTaskForWait()
        {
            _finalizationTask = new Task(() => { /* do nothing */ }, CancellationToken, TaskCreationOptions.LongRunning); //UNDONE:SAQ ?? avoid a lot of LongRunning
            return _finalizationTask;
        }
        internal void StartExecutionTask()
        {
            _executionTask = ExecuteInternalAsync(CancellationToken);
        }
        internal void StartFinalizationTask()
        {
            _finalizationTask?.Start();
        }

        /// <summary>
        /// Gets or sets a flag that is true if the StartExecutionTask() is called in async way.
        /// This flag react faster than testing _executionTask existence.
        /// </summary>
        [field: NonSerialized]
        [JsonIgnore]
        internal bool Started { get; set; }

        internal TaskStatus? GetExecutionTaskStatus() => _executionTask?.Status;

        /* =============================================================================== ATTACHMENTS */
        [field: NonSerialized]
        [JsonIgnore]
        private List<SecurityActivity> _attachments = new();
        internal SecurityActivity[] GetAttachments() => _attachments.ToArray();
        internal void Attach(SecurityActivity activity)
        {
            if (ReferenceEquals(this, activity))
                return;
            if (_attachments.Contains(activity))
                return;
            _attachments.Add(activity);
        }
        public void ClearAttachments()
        {
            _attachments.Clear();
        }

    }
}
