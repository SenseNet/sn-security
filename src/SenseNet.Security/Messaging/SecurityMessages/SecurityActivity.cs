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

        [NonSerialized] private SecurityContext _context;
        /// <summary>
        /// Pointer to the current SecurityContext.
        /// </summary>
        public SecurityContext Context => _context ?? SecurityContext.General;

        /// <summary>
        /// Initializes the instance.
        /// Sets the TypeName property to the name of the .Net type of this instance;
        /// </summary>
        protected SecurityActivity()
        {
            TypeName = this.GetType().Name;
        }

        /// <summary>
        /// Executes the activity by adding it to the activity queue.
        /// </summary>
        /// <param name="context">Current SecurityContext</param>
        /// <param name="waitForComplete">If the value is true (default),
        /// the current thread waits for the full execution on this computer.
        /// Otherwise the method returns immediatelly.</param>
        public void Execute(SecurityContext context, bool waitForComplete = true)
        {
            _context = context;
            SecurityActivityQueue.ExecuteActivity(this);

            if(waitForComplete)
                WaitForComplete();

            if (_executionException != null)
                throw _executionException;
        }

        /// <summary>
        /// Called by an internal component in right order.
        /// </summary>
        internal void ExecuteInternal()
        {
            try
            {
                using (var execLock = DataHandler.AcquireSecurityActivityExecutionLock(this))
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
                SnTrace.Security.WriteError("Error during security activity execution. SA{0} {1}", this.Id, e);
            }
            finally
            {
                Finish();
            }
        }

        /// <summary>
        /// WARNING! Do not use this method in your code.
        /// Called by the message receiver.
        /// </summary>
        public static void Apply(SecurityActivity activity)
        {
            activity.Execute(SecurityContext.General, false);
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
            if (this.BodySize > Configuration.Messaging.DistributableSecurityActivityMaxSize)
                msg = new BigActivityMessage { DatabaseId = this.Id };
            context.MessageProvider.SendMessage(msg);
        }

        /// <summary>
        /// Cusomization point for the activity data persistence.
        /// </summary>
        /// <param name="context">Current SecurityContext to use any security related thing.</param>
        protected abstract void Store(SecurityContext context);
        /// <summary>
        /// Cusomization point for the memory operations based on the activity data.
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
                if (!_finishSignal.WaitOne(Configuration.Messaging.SecuritActivityTimeoutInSeconds * 1000, false))
                {
                    var message = $"SecurityActivity is not finishing on a timely manner (#{this.Id})";
                    throw new SecurityActivityTimeoutException(message);
                }
            }
        }

        [NonSerialized]
        private SecurityActivity _attachedActivity;
        internal SecurityActivity AttachedActivity { get { return _attachedActivity; } private set { _attachedActivity = value; } }

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

        /// <summary>
        /// Serializes an activity for persisting to database.
        /// </summary>
        public static byte[] SerializeActivity(SecurityActivity activity)
        {
            try
            {
                var ms = new MemoryStream();
                var bf = new BinaryFormatter();
                bf.Serialize(ms, activity);
                ms.Flush();
                ms.Position = 0;
                return ms.GetBuffer();
            }
            catch (Exception e) // logged and rethrown
            {
                SnLog.WriteException(e, EventMessage.Error.Serialization, EventId.Serialization);
                throw;
            }
        }
        /// <summary>
        /// Deserializes an activity that comes from the to database.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static SecurityActivity DeserializeActivity(byte[] bytes)
        {
            Stream data = new MemoryStream(bytes);

            var bf = new BinaryFormatter();
            SecurityActivity activity = null;
            try
            {
                activity = (SecurityActivity)bf.Deserialize(data);
            }
            catch (SerializationException e) // logged
            {
                SnLog.WriteException(e, EventMessage.Error.Deserialization, EventId.Serialization);
            }
            return activity;
        }


        internal static class DependencyTools
        {
            internal static bool HasAncestorRelation(SecurityContext ctx, int entityId1, int entityId2)
            {
                var entities = SecurityEntity.PeekEntities(ctx, entityId1, entityId2);
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
                var entities = SecurityEntity.PeekEntities(ctx, descendantId);
                return IsInTree(ctx, entities[0], ancestorId);
            }
            internal static bool IsInTree(SecurityContext ctx, SecurityEntity descendant, int ancestorId)
            {
                return ctx.IsEntityInTree(descendant, ancestorId);
            }

            internal static bool AnyIsInTree(SecurityContext ctx, IEnumerable<int> descendatIds, int ancestorId)
            {
                var entities = SecurityEntity.PeekEntities(ctx, descendatIds.ToArray());
                foreach (var entity in entities)
                    if (ctx.IsEntityInTree(entity, ancestorId))
                        return true;
                return false;
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
            get { return _fromReceiver; }
            set { _fromReceiver = value; }
        }

        [NonSerialized]
        private bool _fromDatabase;
        /// <summary>
        /// Gets or sets whether the activity is loaded from the database.
        /// </summary>
        public bool FromDatabase
        {
            get { return _fromDatabase; }
            set { _fromDatabase = value; }
        }

        [NonSerialized]
        private bool _isUnprocessedActivity;
        /// <summary>
        /// Gets or sets whether the activity is loaded from the database at the system start.
        /// </summary>
        public bool IsUnprocessedActivity
        {
            get { return _isUnprocessedActivity; }
            set { _isUnprocessedActivity = value; }
        }

        [field: NonSerialized]
        internal List<SecurityActivity> WaitingFor { get; private set; } = new List<SecurityActivity>();

        [field: NonSerialized]
        internal List<SecurityActivity> WaitingForMe { get; private set; } = new List<SecurityActivity>();

        internal void WaitFor(SecurityActivity olderActivity)
        {
            // this method must called from thread safe block.
            if (this.WaitingFor.All(x => x.Id != olderActivity.Id))
                this.WaitingFor.Add(olderActivity);
            if (olderActivity.WaitingForMe.All(x => x.Id != this.Id))
                olderActivity.WaitingForMe.Add(this);
        }

        internal void FinishWaiting(SecurityActivity olderActivity)
        {
            // this method must called from thread safe block.
            RemoveDependency(this.WaitingFor, olderActivity);
            RemoveDependency(olderActivity.WaitingForMe, this);
        }
        private static void RemoveDependency(List<SecurityActivity> dependencyList, SecurityActivity activity)
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
