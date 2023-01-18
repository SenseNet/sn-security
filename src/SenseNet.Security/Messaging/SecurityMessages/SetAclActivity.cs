using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that controls Access control list modifications.
    /// </summary>
    [Serializable]
    public class SetAclActivity : SecurityActivity
    {
        private IEnumerable<AclInfo> _acls;
        private List<int> _breaks;
        private List<int> _undoBreaks;
        private List<StoredAce> _entries = new List<StoredAce>();
        private List<StoredAce> _entriesToRemove = new List<StoredAce>();
        private List<int> _emptyAcls = new List<int>();

        public IEnumerable<AclInfo> Acls { get => _acls; set => _acls = value; }
        public List<int> Breaks { get => _breaks; set => _breaks = value; }
        public List<int> UndoBreaks { get => _undoBreaks; set => _undoBreaks = value; }
        public List<StoredAce> Entries { get => _entries; set => _entries = value; }
        public List<StoredAce> EntriesToRemove { get => _entriesToRemove; set => _entriesToRemove = value; }
        public List<int> EmptyAcls { get => _emptyAcls; set => _emptyAcls = value; }

        internal SetAclActivity() { }

        /// <summary>
        /// Initializes a new instance of the SetAclActivity.
        /// </summary>
        public SetAclActivity(IEnumerable<AclInfo> acls, List<int> breaks, List<int> unBreaks)
        {
            _acls = acls;
            _breaks = breaks;
            _undoBreaks = unBreaks;
        }

        /// <summary>
        /// Initializes the data.
        /// </summary>
        protected override void Initialize(SecurityContext context)
        {
            base.Initialize(context);
            if (_acls != null)
            {
                foreach (var acl in _acls)
                {
                    var empty = true;

                    // clearing deny bits from allow bits.
                    foreach (var entry in acl.Entries)
                        entry.AllowBits &= ~entry.DenyBits;

                    // gathering removable entries.
                    foreach (var ace in acl.Entries)
                    {
                        if ((ace.AllowBits | ace.DenyBits) == 0)
                        {
                            _entriesToRemove.Add(new StoredAce
                            {
                                EntityId = acl.EntityId,
                                EntryType = EntryType.Normal,
                                IdentityId = ace.IdentityId,
                                LocalOnly = ace.LocalOnly
                            });
                        }
                        else
                        {
                            empty = false;
                            _entries.Add(new StoredAce
                            {
                                EntityId = acl.EntityId,
                                EntryType =  ace.EntryType,
                                IdentityId = ace.IdentityId,
                                LocalOnly = ace.LocalOnly,
                                AllowBits = ace.AllowBits,
                                DenyBits = ace.DenyBits
                            });
                        }
                    }

                    if (empty)
                        _emptyAcls.Add(acl.EntityId);
                }
            }
        }

        /// <summary>
        /// Stores the modifications in the database.
        /// </summary>
        protected override async Task StoreAsync(SecurityContext context, CancellationToken cancel) //TODO: async: Task.WhenAll?
        {
            var dataHandler = context.SecuritySystem.DataHandler;

            await dataHandler.WritePermissionEntriesAsync(_entries, cancel).ConfigureAwait(false);

            await dataHandler.RemovePermissionEntriesAsync(_entriesToRemove, cancel).ConfigureAwait(false);

            foreach (var entityId in _breaks)
                await dataHandler.BreakInheritanceAsync(entityId, cancel).ConfigureAwait(false);

            foreach (var entityId in _undoBreaks)
                await dataHandler.UnBreakInheritanceAsync(entityId, cancel).ConfigureAwait(false);
        }

        /// <summary>
        /// Applies the modifications in the memory structures.
        /// </summary>
        protected override void Apply(SecurityContext context)
        {
            var relevantAcls = _acls?.Where(x => !_emptyAcls.Contains(x.EntityId)).ToArray() ?? new AclInfo[0];
            context.SecuritySystem.EntityManager.ApplyAclEditing(relevantAcls, _breaks, _undoBreaks, _entriesToRemove, _emptyAcls);
        }

        [NonSerialized]
        // ReSharper disable once InconsistentNaming
        private List<int> __allEntityIds;
        [JsonIgnore]
        internal List<int> AllEntityIds => __allEntityIds ?? (__allEntityIds = CollectEntityIds());

        private List<int> CollectEntityIds()
        {
            var allIds = new List<int>();

            if (_breaks != null)
                allIds.AddRange(_breaks);
            if (_undoBreaks != null)
                allIds.AddRange(_undoBreaks);
            if (_acls != null)
                allIds.AddRange(_acls.Select(a => a.EntityId));
            
            return allIds.Distinct().ToList();
        }

        internal override bool ShouldWaitFor(SecurityActivity olderActivity)
        {
            if(olderActivity is MembershipActivity)
                return true;

            // There aren't any valid scenarios if the olderActivity is ModifySecurityEntityOwnerActivity or MoveSecurityEntityActivity

            if (olderActivity is CreateSecurityEntityActivity createSecurityEntityActivity)
                return AllEntityIds.Contains(createSecurityEntityActivity.EntityId);

            if (olderActivity is DeleteSecurityEntityActivity deleteSecurityEntityActivity)
                return DependencyTools.AnyIsInTree(Context, AllEntityIds, deleteSecurityEntityActivity.EntityId);

            if (olderActivity is SetAclActivity setAclActivity)
                return setAclActivity.AllEntityIds.Intersect(AllEntityIds).Any();

            return false;
        }

    }
}
