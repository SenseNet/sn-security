﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Newtonsoft.Json;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents in-memory information about an access control list. Contains only explicit entries 
    /// and an API for parent walk to aid the permission inheritance algorithm.
    /// Contains helpers method also for building UI structures.
    /// </summary>
    [Serializable]
    public class AclInfo
    {
        [NonSerialized]
        private SecurityEntity _entity;
        [JsonIgnore]
        internal SecurityEntity Entity { get => _entity; set => _entity = value; } // managed in SecurityEntity only

        /// <summary>
        /// Id of the entity.
        /// </summary>
        public int EntityId { get; set; }
        /// <summary>
        /// Gets the inheritance state. True if the entity inherits the permission settings from the ancestors.
        /// </summary>
        public bool Inherits
        {
            get => _entity == null || _entity.IsInherited;
            internal set
            {
                if (_entity == null)
                    return;
                _entity.IsInherited = value;
            }
        }
        /// <summary>
        /// Set of ACEs.
        /// </summary>
        public List<AceInfo> Entries { get; set; }

        /// <summary>
        /// Parent AclInfo.
        /// </summary>
        [JsonIgnore]
        public AclInfo Parent => GetParent();

        private AclInfo GetParent()
        {
            if (Entity == null)
                return null;
            var entity = Entity.Parent;
            while (entity != null)
            {
                if (entity.Acl != null)
                    return entity.Acl;
                entity = entity.Parent;
            }
            return null;
        }

        internal AclInfo() { }

        /// <summary>
        /// Initializes a new instance of the AclInfo.
        /// </summary>
        public AclInfo(int entityId)
        {
            EntityId = entityId;
            Entries = new List<AceInfo>();
        }

        internal AccessControlList ToAccessControlList(int requestedEntityId, EntryType entryType)
        {
            var aces = new Dictionary<int, AccessControlEntry>();
            var localOnlyAces = new Dictionary<int, AccessControlEntry>();

            var aclInfo = this;
            while (aclInfo != null)
            {
                foreach (var aceInfo in aclInfo.Entries.Where(x => x.EntryType == entryType))
                {
                    var isLocalAcl = aclInfo.EntityId == requestedEntityId;
                    AccessControlEntry ace;
                    if (aceInfo.LocalOnly)
                    {
                        if (this == aclInfo && isLocalAcl)
                        {
                            if (!localOnlyAces.TryGetValue(aceInfo.IdentityId, out ace))
                            {
                                ace = CreateEmptyAce(aceInfo);
                                localOnlyAces.Add(ace.IdentityId, ace);
                            }
                            // ReSharper disable once ConditionIsAlwaysTrueOrFalse
                            ProcessPermissions(aclInfo, aceInfo, ace, isLocalAcl);
                        }
                    }
                    else
                    {
                        if (!aces.TryGetValue(aceInfo.IdentityId, out ace))
                        {
                            ace = CreateEmptyAce(aceInfo);
                            aces.Add(ace.IdentityId, ace);
                        }
                        ProcessPermissions(aclInfo, aceInfo, ace, isLocalAcl);
                    }
                }
                if (!aclInfo.Inherits)
                    break;
                aclInfo = aclInfo.Parent;
            }

            return new AccessControlList
            {
                EntityId = requestedEntityId,
                Inherits = EntityId != requestedEntityId || Inherits,
                Entries = aces.Values.Concat(localOnlyAces.Values).OrderBy(x => x.IdentityId).ThenBy(x => x.LocalOnly).ToArray()
            };
        }
        private AccessControlEntry CreateEmptyAce(AceInfo aceInfo)
        {
            var perms = new Permission[PermissionTypeBase.PermissionCount];
            for (var i = 0; i < perms.Length; i++)
                perms[i] = new Permission { Name = PermissionTypeBase.GetPermissionTypeByIndex(i).Name };

            return new AccessControlEntry
            {
                EntryType = aceInfo.EntryType,
                IdentityId = aceInfo.IdentityId,
                LocalOnly = aceInfo.LocalOnly,
                Permissions = perms
            };
        }
        private void ProcessPermissions(AclInfo aclInfo, AceInfo aceInfo, AccessControlEntry ace, bool isLocal)
        {
            var perms = ace.Permissions;
            for (var i = 0; i < ace.Permissions.Length; i++)
            {
                var mask = 1ul << i;
                var perm = perms[i];
                if (!perm.Allow && !perm.Deny)
                {
                    if ((aceInfo.DenyBits & mask) != 0)
                    {
                        perm.Deny = true;
                        if (!isLocal)
                            perm.DenyFrom = aclInfo.EntityId;
                    }
                    else if ((aceInfo.AllowBits & mask) == mask)
                    {
                        perm.Allow = true;
                        if (!isLocal)
                            perm.AllowFrom = aclInfo.EntityId;
                    }
                }
            }
        }

        internal static AccessControlList CreateEmptyAccessControlList(int entityId, bool inherits)
        {
            return new AccessControlList
            {
                EntityId = entityId,
                Inherits = inherits,
                Entries = new AccessControlEntry[0]
            };
        }

        /// <summary> Used for getting permission. </summary>
        internal void AggregateLocalOnlyValues(List<int> identities, ref ulong allow, ref ulong deny)
        {
            foreach (var permSet in Entries)
            {
                if (!permSet.LocalOnly)
                    continue;
                if (!identities.Contains(permSet.IdentityId))
                    continue;
                allow |= permSet.AllowBits;
                deny |= permSet.DenyBits;
            }
        }
        /// <summary> Used for getting permission. </summary>
        internal void AggregateEffectiveValues(List<int> identities, ref ulong allow, ref ulong deny)
        {
            foreach (var permSet in Entries)
            {
                if (permSet.LocalOnly)
                    continue;
                if (!identities.Contains(permSet.IdentityId))
                    continue;
                allow |= permSet.AllowBits;
                deny |= permSet.DenyBits;
            }
        }
        /// <summary> Used for getting permission in a permission query. </summary>
        internal void AggregateLocalOnlyValues(List<int> identities, EntryType entryType, ref ulong allow, ref ulong deny)
        {
            foreach (var permSet in Entries.Where(e => e.EntryType == entryType))
            {
                if (!permSet.LocalOnly)
                    continue;
                if (!identities.Contains(permSet.IdentityId))
                    continue;
                allow |= permSet.AllowBits;
                deny |= permSet.DenyBits;
            }
        }
        /// <summary> Used for getting permission in a permission query. </summary>
        internal void AggregateEffectiveValues(List<int> identities, EntryType entryType, ref ulong allow, ref ulong deny)
        {
            foreach (var permSet in Entries.Where(e => e.EntryType == entryType))
            {
                if (permSet.LocalOnly)
                    continue;
                if (!identities.Contains(permSet.IdentityId))
                    continue;
                allow |= permSet.AllowBits;
                deny |= permSet.DenyBits;
            }
        }

        /// <summary> Used for getting effective entries. </summary>
        internal void AggregateLevelOnlyValues(List<AceInfo> aces, IEnumerable<int> relatedIdentities = null, EntryType? entryType = null)
        {
            foreach (var ace in Entries)
            {
                if (!ace.LocalOnly)
                    continue;
                if (entryType != null && ace.EntryType != entryType.Value)
                    continue;
                // ReSharper disable once PossibleMultipleEnumeration
                if (relatedIdentities == null || relatedIdentities.Contains(ace.IdentityId))
                {
                    var refAce = EnsureAce(ace, aces);
                    refAce.AllowBits |= ace.AllowBits;
                    refAce.DenyBits |= ace.DenyBits;
                }
            }
        }
        /// <summary> Used for getting effective entries. </summary>
        internal void AggregateEffectiveValues(List<AceInfo> aces, IEnumerable<int> relatedIdentities = null, EntryType? entryType = null)
        {
            foreach (var ace in Entries)
            {
                if (ace.LocalOnly)
                    continue;
                if (entryType != null && ace.EntryType != entryType.Value)
                    continue;
                // ReSharper disable once PossibleMultipleEnumeration
                if (relatedIdentities == null || relatedIdentities.Contains(ace.IdentityId))
                {
                    var refAce = EnsureAce(ace, aces);
                    refAce.AllowBits |= ace.AllowBits;
                    refAce.DenyBits |= ace.DenyBits;
                }
            }
        }
        /// <summary> Used for getting effective entries. </summary>
        private AceInfo EnsureAce(AceInfo predicate, List<AceInfo> refAces)
        {
            foreach (var refAce in refAces)
                if (refAce.EntryType == predicate.EntryType && refAce.IdentityId == predicate.IdentityId && refAce.LocalOnly == predicate.LocalOnly)
                    return refAce;
            var newAce = new AceInfo { EntryType = predicate.EntryType, IdentityId = predicate.IdentityId, LocalOnly = predicate.LocalOnly };
            refAces.Add(newAce);
            return newAce;
        }

        internal AclInfo Copy(EntryType? entryType = null)
        {
            var entries = entryType == null
                ? Entries.Select(x => x.Copy()).ToList()
                : Entries.Where(x => x.EntryType == entryType.Value).Select(x => x.Copy()).ToList();

            return new AclInfo(EntityId) { Entries = entries };
        }

        /// <summary>
        /// Converts the information of this instance to its equivalent string representation.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
        public override string ToString()
        {
            // "+E1|+U1:____++++,+G1:____++++"

            var sb = new StringBuilder();
            sb.Append(Inherits ? '+' : '-');
            sb.Append("(" + EntityId + ")");
            sb.Append('|');
            var count = 0;
            foreach (var entry in Entries.OrderBy(x => x.IdentityId).ThenBy(x => x.LocalOnly))
            {
                if (count++ > 0)
                    sb.Append(',');
                sb.Append(entry);
            }
            return sb.ToString();

        }
    }
}
