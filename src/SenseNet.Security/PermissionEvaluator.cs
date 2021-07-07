using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents value of a permission
    /// </summary>
    public enum PermissionValue
    {
        /// <summary>
        /// Means: the associated permission is not controlled in this case.
        /// </summary>
        Undefined,
        /// <summary>
        /// The associated permission is granted.
        /// </summary>
        Allowed,
        /// <summary>
        /// The associated permission is explicitly denied.
        /// </summary>
        Denied
    }

    /// <summary>
    /// Central class for evaluating permission requests. It is responsible for collecting 
    /// the relevant identities (mainly groups) for the user in context and deciding whether 
    /// a certain permission is allowed or denied for that user.
    /// </summary>
    internal class PermissionEvaluator
    {
        private readonly SecurityContext _securityContext;
        private readonly SecurityEntityManager _entityManager;
        internal PermissionEvaluator(SecurityContext securityContext)
        {
            _securityContext = securityContext;
            _entityManager = securityContext.SecuritySystem.EntityManager;
        }

        internal void Initialize()
        {
        }

        internal bool HasPermission(int userId, int entityId, int ownerId, params PermissionTypeBase[] permissions)
        {
            return HasPermission(userId, entityId, ownerId, null, permissions);
        }
        internal bool HasPermission(int userId, int entityId, int ownerId, EntryType? entryType, params PermissionTypeBase[] permissions)
        {
            var value = GetPermission(userId, entityId, ownerId, entryType, permissions);
            return value == PermissionValue.Allowed;
        }
        internal PermissionValue GetPermission(int userId, int entityId, int ownerId, params PermissionTypeBase[] permissions)
        {
            return GetPermission(userId, entityId, ownerId, null, permissions);
        }
        internal PermissionValue GetPermission(int userId, int entityId, int ownerId, EntryType? entryType, params PermissionTypeBase[] permissions)
        {
            if (userId == Configuration.Identities.SystemUserId)
                return PermissionValue.Allowed;

            _entityManager.EnterReadLock();
            try
            {
                return GetPermissionSafe(userId, entityId, ownerId, entryType, permissions);
            }
            finally
            {
                _entityManager.ExitReadLock();
            }
        }
        internal PermissionValue GetPermissionSafe(int userId, int entityId, int ownerId, params PermissionTypeBase[] permissions)
        {
            return GetPermissionSafe(userId, entityId, ownerId, null, permissions);
        }
        [SuppressMessage("ReSharper", "ConvertIfStatementToReturnStatement")]
        internal PermissionValue GetPermissionSafe(int userId, int entityId, int ownerId, EntryType? entryType, params PermissionTypeBase[] permissions)
        {
            if (userId == Configuration.Identities.SystemUserId)
                return PermissionValue.Allowed;

            //==>
            var identities = GetIdentities(userId, ownerId, entityId);
            var allow = 0ul;
            var deny = 0ul;

            var firstAcl = _entityManager.GetFirstAclSafe(_securityContext, entityId, true);

            if (firstAcl == null)
                return PermissionValue.Undefined;

            if (entryType == null)
            {
                if (entityId == firstAcl.EntityId)
                    firstAcl.AggregateLocalOnlyValues(identities, ref allow, ref deny);
                for (var aclInfo = firstAcl; aclInfo != null; aclInfo = aclInfo.Inherits ? aclInfo.Parent : null)
                    aclInfo.AggregateEffectiveValues(identities, ref allow, ref deny);
            }
            else
            {
                if (entityId == firstAcl.EntityId)
                    firstAcl.AggregateLocalOnlyValues(identities, entryType.Value, ref allow, ref deny);
                for (var aclInfo = firstAcl; aclInfo != null; aclInfo = aclInfo.Inherits ? aclInfo.Parent : null)
                    aclInfo.AggregateEffectiveValues(identities, entryType.Value, ref allow, ref deny);
            }
            //==<

            var mask = PermissionTypeBase.GetPermissionMask(permissions);
            if ((deny & mask) != 0)
                return PermissionValue.Denied;
            if ((allow & mask) != mask)
                return PermissionValue.Undefined;
            return PermissionValue.Allowed;
        }

        internal bool HasSubTreePermission(int userId, int entityId, int ownerId, params PermissionTypeBase[] permissions)
        {
            var value = GetSubtreePermission(userId, entityId, ownerId, permissions);
            return value == PermissionValue.Allowed;
        }
        internal PermissionValue GetSubtreePermission(int userId, int entityId, int ownerId, params PermissionTypeBase[] permissions)
        {
            if (userId == Configuration.Identities.SystemUserId)
                return PermissionValue.Allowed;

            var identities = GetIdentities(userId, ownerId, entityId);
            _entityManager.EnterReadLock();
            try
            {
                var entity = _entityManager.GetEntitySafe(_securityContext, entityId, true);
                var firstAcl = _entityManager.GetFirstAclSafe(_securityContext, entityId, true);

                //======== #1: start bits: get permission bits
                //==>

                var allow = 0ul;
                var deny = 0ul;

                if (entityId == firstAcl.EntityId)
                    firstAcl.AggregateLocalOnlyValues(identities, ref allow, ref deny);
                for (var permInfo = firstAcl; permInfo != null; permInfo = permInfo.Inherits ? permInfo.Parent : null)
                    permInfo.AggregateEffectiveValues(identities, ref allow, ref deny);
                //==<

                var mask = PermissionTypeBase.GetPermissionMask(permissions);
                if ((deny & mask) != 0)
                    return PermissionValue.Denied;
                if ((allow & mask) != mask)
                    return PermissionValue.Undefined;

                // doesn't depend from the value of the entity's Inherits (need to evaluate through the breaks)
                // doesn't depend from the value of the LocalOnly (need to evaluate any entry)
                foreach (var descendantEntity in new EntityTreeWalker(entity))
                {
                    // if nearest holder is different, this entity is irrelevant (there is no entry to evaluate)
                    if (!descendantEntity.HasExplicitAcl)
                        continue;

                    // only this level is sufficient to evaluate because any difference from "allow" causes exit instantly

                    // filtered by relevant identities
                    AceInfo[] relevantAces;
                    try
                    {
                        relevantAces = GetExplicitEntriesSafe(descendantEntity.Id, identities).ToArray();
                    }
                    catch (EntityNotFoundException) // catch only: well known exception
                    {
                        // do nothing because entity was deleted
                        continue;
                    }

                    // different evaluation that depends on the inheritance continuity
                    if (descendantEntity.IsInherited)
                    {
                        // if inherited, only denied bits play
                        // ReSharper disable once LoopCanBeConvertedToQuery
                        foreach (var ace in relevantAces)
                            deny |= ace.DenyBits;
                        if ((deny & mask) != 0uL)
                            return PermissionValue.Denied;
                    }
                    else
                    {
                        // if broken, need to recalculate allow and deny bits too.
                        allow = 0ul;
                        deny = 0ul;
                        var hasLocalOnly = false;
                        // on this level need to explicit "allow"
                        foreach (var ace in relevantAces)
                        {
                            allow |= ace.AllowBits;
                            deny |= ace.DenyBits;
                            hasLocalOnly |= ace.LocalOnly;
                        }
                        // return if inadequate
                        if ((deny & mask) != 0)
                            return PermissionValue.Denied;
                        if ((allow & mask) != mask)
                            return PermissionValue.Undefined;

                        // if there is any local only entry, the children decide to exit or move forward.
                        if (hasLocalOnly)
                        {
                            // move forward if the entity is a leaf (children is null)
                            if (descendantEntity.Children != null)
                            {
                                foreach (var childEntity in descendantEntity.Children)
                                {
                                    var value = GetPermissionSafe(userId, childEntity.Id, childEntity.OwnerId, permissions);
                                    // return if not allowed
                                    if (value != PermissionValue.Allowed)
                                        return value;
                                    // move forward
                                }
                            }
                        }
                    }
                    // walk forward on the tree
                }
            }
            finally
            {
                _entityManager.ExitReadLock();
            }
            return PermissionValue.Allowed;
        }

        internal List<AceInfo> GetEffectiveEntries(int entityId, IEnumerable<int> relatedIdentities = null, EntryType? entryType = null)
        {
            _entityManager.EnterReadLock();
            try
            {
                return GetEffectiveEntriesSafe(entityId, relatedIdentities, entryType);
            }
            finally
            {
                _entityManager.ExitReadLock();
            }
        }
        internal List<AceInfo> GetEffectiveEntriesSafe(int entityId, IEnumerable<int> relatedIdentities = null, EntryType? entryType = null)
        {
            var aces = new List<AceInfo>();

            //==>
            var firstAcl = _entityManager.GetFirstAclSafe(_securityContext, entityId, true);
            if (firstAcl != null)
            {
                relatedIdentities = relatedIdentities?.ToArray();
                if (entityId == firstAcl.EntityId)
                    firstAcl.AggregateLevelOnlyValues(aces, relatedIdentities, entryType);
                for (var aclInfo = firstAcl; aclInfo != null; aclInfo = aclInfo.Inherits ? aclInfo.Parent : null)
                    aclInfo.AggregateEffectiveValues(aces, relatedIdentities, entryType);
            }
            //==<

            return aces;
        }

        internal List<AceInfo> GetExplicitEntries(int entityId, IEnumerable<int> relatedIdentities = null, EntryType? entryType = null)
        {
            return GetExplicitEntriesSafe(entityId, _entityManager.GetFirstAcl(_securityContext, entityId, true), relatedIdentities, entryType);
        }
        internal List<AceInfo> GetExplicitEntriesSafe(int entityId, IEnumerable<int> relatedIdentities = null, EntryType? entryType = null)
        {
            return GetExplicitEntriesSafe(entityId, _entityManager.GetFirstAclSafe(_securityContext, entityId, true), relatedIdentities, entryType);
        }
        private static List<AceInfo> GetExplicitEntriesSafe(int entityId, AclInfo acl, IEnumerable<int> relatedIdentities, EntryType? entryType)
        {
            IEnumerable<AceInfo> aces = null;

            //==>
            if (acl != null && entityId == acl.EntityId)
            {
                aces = relatedIdentities == null
                    ? acl.Entries.Select(x => x.Copy())
                    : acl.Entries.Where(x => relatedIdentities.Contains(x.IdentityId)).Select(x => x.Copy());

                if (entryType != null)
                    aces = aces.Where(x => x.EntryType == entryType).ToList();
            }
            //==<

            return aces?.ToList() ?? new List<AceInfo>();
        }

        /*------------------------------------------------------------------------------------------ Tools */

        internal List<int> GetGroups(int userId, int ownerId, int entityId)
        {
            var identities = new List<int>();
            CollectIdentities(userId, ownerId, entityId, identities);
            return identities;
        }
        internal List<int> GetIdentities(int userId, int ownerId, int entityId)
        {
            var identities = new List<int> { userId };
            CollectIdentities(userId, ownerId, entityId, identities);
            return identities;
        }
        private void CollectIdentities(int userId, int ownerId, int entityId, List<int> collection)
        {
            if (_securityContext.Cache.Membership.TryGetValue(userId, out var flattenedGroups))
                collection.AddRange(flattenedGroups);

            if (userId != Configuration.Identities.VisitorUserId)
                collection.Add(Configuration.Identities.EveryoneGroupId);

            if (userId == ownerId)
                collection.Add(Configuration.Identities.OwnerGroupId);

            var extension = _securityContext.GetDynamicGroups(entityId);
            if(extension==null)
                return;

            foreach (var identity in FlattenDynamicGroups(extension))
                if (!collection.Contains(identity))
                    collection.Add(identity);
        }
        private IEnumerable<int> FlattenDynamicGroups(IEnumerable<int> extension)
        {
            var flattened = new List<int>();
            foreach (var groupId in extension)
            {
                if (!flattened.Contains(groupId))
                    flattened.Add(groupId);
                foreach (var id in PermissionQuery.GetParentGroups(_securityContext, groupId, false))
                    if (!flattened.Contains(id))
                        flattened.Add(id);
            }
            return flattened;
        }

        [ExcludeFromCodeCoverage]
        internal string _traceEffectivePermissionValues(int entityId, int userId, int ownerId)
        {
            var values = new char[PermissionTypeBase.PermissionCount];
            foreach (var permType in PermissionTypeBase.GetPermissionTypes())
            {
                var val = GetPermission(userId, entityId, ownerId, permType);
                char c;
                switch (val)
                {
                    case PermissionValue.Undefined: c = '_'; break;
                    case PermissionValue.Allowed: c = '+'; break;
                    case PermissionValue.Denied: c = '-'; break;
                    default: throw new NotSupportedException("Unknown PermissionValue: " + val);
                }
                values[values.Length - permType.Index - 1] = c;
            }
            return new string(values);
        }
        [ExcludeFromCodeCoverage]
        internal string _traceMembership()
        {
            var sb = new StringBuilder();
            foreach (var item in _securityContext.Cache.Membership)
            {
                sb.Append("(" + item.Key + ")").Append(": [");
                sb.Append(string.Join(", ", item.Value.Select(g => "(" + g + ")")));
                sb.AppendLine("]");
            }
            return sb.ToString();
        }
    }
}
