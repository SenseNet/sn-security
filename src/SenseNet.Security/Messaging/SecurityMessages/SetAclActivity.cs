using System;
using System.Collections.Generic;
using System.Linq;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Represents an activity that controls Access control list modifications.
    /// </summary>
    [Serializable]
    public class SetAclActivity : SecurityActivity
    {
        private readonly IEnumerable<AclInfo> _acls;
        private readonly List<int> _breaks;
        private readonly List<int> _undoBreaks;
        private readonly List<StoredAce> _entries = new List<StoredAce>();
        private readonly List<StoredAce> _entriesToRemove = new List<StoredAce>();
        private readonly List<int> _emptyAcls = new List<int>();

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
        protected override void Store(SecurityContext context)
        {
            var dataHandler = context.SecuritySystem.DataHandler;
            dataHandler.WritePermissionEntries(_entries);
            dataHandler.RemovePermissionEntries(context, _entriesToRemove);

            foreach (var entityId in _breaks)
                dataHandler.BreakInheritance(context, entityId);

            foreach (var entityId in _undoBreaks)
                dataHandler.UnBreakInheritance(context, entityId);
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

        internal override bool MustWaitFor(SecurityActivity olderActivity)
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
