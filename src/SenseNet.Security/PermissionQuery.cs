﻿using System;
using System.Collections.Generic;
using System.Linq;

namespace SenseNet.Security
{
    /// <summary>
    /// Contains an internal API for querying permission values in the system by entities, identities or permission types.
    /// </summary>
    internal class PermissionQuery
    {
        private readonly SecurityEntityManager _entityManager;
        private readonly SecurityCache _cache;

        public PermissionQuery(SecurityEntityManager entityManager, SecurityCache cache)
        {
            _entityManager = entityManager;
            _cache = cache;
        }

        public Dictionary<PermissionTypeBase, int> GetExplicitPermissionsInSubtree(SecurityContext context, int entityId, int[] identities, bool includeRoot)
        {
            _entityManager.EnterReadLock();
            try
            {
                var counters = new int[PermissionTypeBase.PermissionCount];

                var root = _entityManager.GetEntitySafe(entityId, true);
                foreach (var entity in new EntityTreeWalker(root))
                {
                    // step forward if there is no any setting
                    if (!entity.HasExplicitAcl || entity.Id == entityId && !includeRoot)
                        continue;

                    // if broken, adding existing parent-s effective identities because all identities are related.
                    var localBits = new PermissionBitMask();
                    if (!entity.IsInherited && entity.Parent != null && (includeRoot || entity.Parent.Id != entityId))
                        CollectPermissionsFromLocalAces(context.Evaluator.GetEffectiveEntriesSafe(entity.Parent.Id, identities, EntryType.Normal), localBits);

                    // adding explicit identities
                    CollectPermissionsFromAces(context.Evaluator.GetExplicitEntriesSafe(entity.Id, identities, EntryType.Normal), PermissionLevel.AllowedOrDenied, counters, localBits);
                }

                var result = new Dictionary<PermissionTypeBase, int>();
                for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                    result.Add(PermissionTypeBase.GetPermissionTypeByIndex(i), counters[i]);

                return result;
            }
            finally
            {
                _entityManager.ExitReadLock();
            }
        }

        /******************************************************************************************************* Related Identities */

        public IEnumerable<int> GetRelatedIdentities(SecurityContext context, int entityId, PermissionLevel level)
        {
            var identities = new List<int>();
            _entityManager.EnterReadLock();
            try
            {
                var root = _entityManager.GetEntitySafe(entityId, true);
                foreach (var entity in new EntityTreeWalker(root))
                {
                    // step forward if there is no any setting
                    if (!entity.HasExplicitAcl)
                        continue;

                    // if broken, adding existing parent-s effective identities because all identities are related.
                    if (!entity.IsInherited && entity.Parent != null)
                        CollectIdentitiesFromAces(context.Evaluator.GetEffectiveEntriesSafe(entity.Parent.Id, null, EntryType.Normal), level, identities);

                    // adding explicit identities
                    CollectIdentitiesFromAces(context.Evaluator.GetExplicitEntriesSafe(entity.Id, null, EntryType.Normal), level, identities);
                }
            }
            finally
            {
                _entityManager.ExitReadLock();
            }
            return identities;
        }
        private void CollectIdentitiesFromAces(List<AceInfo> aces, PermissionLevel level, List<int> identities)
        {
            foreach (var ace in aces)
            {
                if (!identities.Contains(ace.IdentityId))
                {
                    if (level == PermissionLevel.Allowed && ace.AllowBits == 0uL)
                        continue;
                    if (level == PermissionLevel.Denied && ace.DenyBits == 0uL)
                        continue;
                    if (!identities.Contains(ace.IdentityId))
                        identities.Add(ace.IdentityId);
                }
            }
        }

        /****************************************************************************************************** Related Permissions */

        public Dictionary<PermissionTypeBase, int> GetRelatedPermissions(SecurityContext context, int entityId, PermissionLevel level, bool explicitOnly, int identityId, Func<int, bool> isEnabled)
        {
            if (!explicitOnly)
                throw new NotSupportedException("Not supported in this version. Use explicitOnly = true");

            _entityManager.EnterReadLock();
            try
            {
                var counters = new int[PermissionTypeBase.PermissionCount];

                var identities = new[] { identityId };

                var root = _entityManager.GetEntitySafe(entityId, true);
                foreach (var entity in new EntityTreeWalker(root))
                {
                    // step forward if there is no any setting
                    if (!entity.HasExplicitAcl)
                        continue;

                    if (!isEnabled(entity.Id))
                        continue;

                    // if broken, adding existing parent-s effective identities because all identities are related.
                    var localBits = new PermissionBitMask();
                    if (!entity.IsInherited && entity.Parent != null)
                        CollectPermissionsFromLocalAces(context.Evaluator.GetEffectiveEntriesSafe(entity.Parent.Id, identities, EntryType.Normal), localBits);

                    // adding explicit identities
                    CollectPermissionsFromAces(context.Evaluator.GetExplicitEntriesSafe(entity.Id, identities, EntryType.Normal), level, counters, localBits);
                }

                var result = new Dictionary<PermissionTypeBase, int>();
                for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                    result.Add(PermissionTypeBase.GetPermissionTypeByIndex(i), counters[i]);

                return result;
            }
            finally
            {
                _entityManager.ExitReadLock();
            }
        }
        private void CollectPermissionsFromLocalAces(List<AceInfo> aces, PermissionBitMask localBits)
        {
            foreach (var ace in aces)
            {
                localBits.AllowBits |= ace.AllowBits;
                localBits.DenyBits |= ace.DenyBits;
            }
        }
        private void CollectPermissionsFromAces(List<AceInfo> aces, PermissionLevel level, int[] counters, PermissionBitMask localBits)
        {
            // Aggregate aces and switch of the 'used bits' in the local only permission bit set.
            foreach (var ace in aces)
            {
                SetPermissionsCountersByPermissionLevel(counters, level, ace.AllowBits, ace.DenyBits);
                localBits.AllowBits &= ~ace.AllowBits;
                localBits.DenyBits &= ~ace.DenyBits ;
            }
            // Finally play the rest bits (all broken bits are switched in that is not used in any explicit entry)
            SetPermissionsCountersByPermissionLevel(counters, level, localBits.AllowBits, localBits.DenyBits);
        }
        private void SetPermissionsCountersByPermissionLevel(int[] counters, PermissionLevel level, ulong allowBits, ulong denyBits)
        {
            // ReSharper disable once SwitchStatementMissingSomeCases
            switch (level)
            {
                case PermissionLevel.Allowed:
                    IncrementCounters(allowBits, counters);
                    break;
                case PermissionLevel.Denied:
                    IncrementCounters(denyBits, counters);
                    break;
                case PermissionLevel.AllowedOrDenied:
                    IncrementCounters(allowBits, counters);
                    IncrementCounters(denyBits, counters);
                    break;
            }
        }
        private void IncrementCounters(ulong bits, int[] counters)
        {
            var mask = 1uL;
            var b = bits;
            foreach (var pt in PermissionTypeBase.GetPermissionTypes())
            {
                if ((b & mask) > 0)
                    counters[pt.Index]++;
                mask <<= 1;
            }
        }

        /********************************************************************************************************* Related Entities */

        public IEnumerable<int> GetRelatedEntities(SecurityContext context, int entityId, PermissionLevel level, bool explicitOnly, int identityId, IEnumerable<PermissionTypeBase> permissionTypes)
        {
            if (!explicitOnly)
                throw new NotSupportedException("Not supported in this version. Use explicitOnly = true");

            _entityManager.EnterReadLock();
            try
            {
                var entityIds = new List<int>();

                var mask = PermissionTypeBase.GetPermissionMask(permissionTypes);
                var identities = new[] { identityId };

                var root = _entityManager.GetEntitySafe(entityId, true);
                foreach (var entity in new EntityTreeWalker(root))
                {
                    // step forward if there is no any setting
                    if (!entity.HasExplicitAcl)
                        continue;

                    var added = false;
                    if (!entity.IsInherited && entity.Parent != null)
                    {
                        if (HasBitsByEffectiveAces(context.Evaluator.GetEffectiveEntriesSafe(entity.Parent.Id, identities, EntryType.Normal), level, mask))
                        {
                            entityIds.Add(entity.Id);
                            added = true;
                        }
                    }

                    // adding explicit identities
                    if (!added)
                        if (HasBitsByExplicitAces(context.Evaluator.GetExplicitEntriesSafe(entity.Id, identities, EntryType.Normal), level, mask))
                            entityIds.Add(entity.Id);
                }

                return entityIds;
            }
            finally
            {
                _entityManager.ExitReadLock();
            }

        }
        private bool HasBitsByEffectiveAces(List<AceInfo> aces, PermissionLevel level, ulong mask)
        {
            var permBits = new PermissionBitMask();
            foreach (var ace in aces)
            {
                if (!ace.LocalOnly)
                {
                    permBits.AllowBits |= ace.AllowBits;
                    permBits.DenyBits |= ace.DenyBits;
                }
            }
            return HasBits(permBits, level, mask);
        }
        private bool HasBitsByExplicitAces(List<AceInfo> aces, PermissionLevel level, ulong mask)
        {
            var permBits = new PermissionBitMask();
            foreach (var ace in aces)
            {
                    permBits.AllowBits |= ace.AllowBits;
                    permBits.DenyBits |= ace.DenyBits;
            }
            return HasBits(permBits, level, mask);
        }
        private bool HasBits(PermissionBitMask permBits, PermissionLevel level, ulong permissionMask)
        {
            switch (level)
            {
                case PermissionLevel.Allowed:
                    return (permBits.AllowBits & permissionMask) != 0;
                case PermissionLevel.Denied:
                    return (permBits.DenyBits & permissionMask) != 0;
                case PermissionLevel.AllowedOrDenied:
                    return ((permBits.AllowBits | permBits.DenyBits) & permissionMask) != 0;
                default:
                    throw new NotSupportedException("Not supported PermissionLevel: " + level);
            }
        }

        /**************************************************************************************************** Related Identities #2 */

        public IEnumerable<int> GetRelatedIdentities(SecurityContext context, int entityId, PermissionLevel level, IEnumerable<PermissionTypeBase> permissionTypes)
        {
            _entityManager.EnterReadLock();
            try
            {
                var identities = new List<int>();
                var mask = PermissionTypeBase.GetPermissionMask(permissionTypes);
                var root = _entityManager.GetEntitySafe(entityId, true);
                foreach (var entity in new EntityTreeWalker(root))
                {
                    // step forward if there is no any setting
                    if (!entity.HasExplicitAcl)
                        continue;

                    // if broken, adding existing parent-s effective identities because all identities are related.
                    if (!entity.IsInherited && entity.Parent != null)
                        CollectIdentitiesFromAces(context.Evaluator.GetEffectiveEntriesSafe(entity.Parent.Id, null, EntryType.Normal), level, mask, identities);

                    // adding explicit identities
                    CollectIdentitiesFromAces(context.Evaluator.GetExplicitEntriesSafe(entity.Id, null, EntryType.Normal), level, mask, identities);
                }
                return identities;
            }
            finally
            {
                _entityManager.ExitReadLock();
            }
        }
        private void CollectIdentitiesFromAces(List<AceInfo> aces, PermissionLevel level, ulong mask, List<int> identities)
        {
            foreach (var ace in aces)
                if (!identities.Contains(ace.IdentityId))
                    if(HasBits(ace.AllowBits, ace.DenyBits, level, mask))
                        if(!identities.Contains(ace.IdentityId))
                            identities.Add(ace.IdentityId);
        }
        private bool HasBits(ulong allowBits, ulong denyBits, PermissionLevel level, ulong permissionMask)
        {
            switch (level)
            {
                case PermissionLevel.Allowed:
                    return (allowBits & permissionMask) != 0;
                case PermissionLevel.Denied:
                    return (denyBits & permissionMask) != 0;
                case PermissionLevel.AllowedOrDenied:
                    return ((allowBits | denyBits) & permissionMask) != 0;
                default:
                    throw new NotSupportedException("Not supported PermissionLevel: " + level);
            }
        }

        /********************************************************************************************* Related Entities one level#2 */

        public IEnumerable<int> GetRelatedEntitiesOneLevel(SecurityContext context, int entityId, PermissionLevel level, int identityId, IEnumerable<PermissionTypeBase> permissionTypes)
        {
            _entityManager.EnterReadLock();
            try
            {
                var result = new List<int>();
                var identities = new[] { identityId };
                var mask = PermissionTypeBase.GetPermissionMask(permissionTypes);
                var root = _entityManager.GetEntitySafe(entityId, true);
                foreach (var childEntity in root.Children)
                {
                    var aces = context.Evaluator.GetEffectiveEntriesSafe(childEntity.Id, identities, EntryType.Normal);
                    if (aces.Any(a => HasBits(a.AllowBits, a.DenyBits, level, mask)))
                        result.Add(childEntity.Id);
                }
                return result;
            }
            finally
            {
                _entityManager.ExitReadLock();
            }
        }

        /********************************************************************************************* Allowed Users */

        public IEnumerable<int> GetAllowedUsers(SecurityContext context, int entityId, IEnumerable<PermissionTypeBase> permissions)
        {
            var ownerId = context.GetOwnerId(entityId);
            var permArray = permissions.ToArray();
            var entries = context.Evaluator.GetEffectiveEntries(entityId);
            var identities = entries.Select(e => e.IdentityId).ToArray();
            var users = GetFlattenedUsers(context, identities);
            var allowedIdentities = users
                .Where(u => context.Evaluator.HasPermission(u, entityId, ownerId, EntryType.Normal, permArray))
                .ToArray();
            return allowedIdentities;
        }
        private IEnumerable<int> GetFlattenedUsers(SecurityContext context, IEnumerable<int> identities)
        {
            var flattenedUsers = new List<int>();

            var groups = new List<SecurityGroup>();
            foreach (var identity in identities.Distinct())
            {
                if (_cache.Groups.TryGetValue(identity, out var group))
                {
                    if (!groups.Contains(group))
                        groups.Add(group);
                }
                else
                {
                    flattenedUsers.Add(identity);
                }
            }

            foreach (var group in groups)
            {
                var allUsersInGroup = _cache.GetAllUsersInGroup(group);
                foreach (var userId in allUsersInGroup)
                {
                    if (!flattenedUsers.Contains(userId))
                        flattenedUsers.Add(userId);
                }
            }
            return flattenedUsers;
        }

        /********************************************************************************************* Parent Groups */

        public IEnumerable<int> GetParentGroups(SecurityContext context, int identityId, bool directOnly)
        {
            if (_cache.Groups.TryGetValue(identityId, out var group))
                return directOnly ? GetDirectOnlyParentGroups(group) : GetAllParentGroups(context, group);
            return directOnly ? GetDirectOnlyParentGroups(context, identityId) : GetAllParentGroups(context, identityId);
        }
        private IEnumerable<int> GetAllParentGroups(SecurityContext context, SecurityGroup group)
        {
            return _cache.GetAllParentGroupIds(group);
        }
        private IEnumerable<int> GetAllParentGroups(SecurityContext context, int userId)
        {
            if (_cache.Membership.TryGetValue(userId, out var groupIds))
                return groupIds;
            return new int[0];
        }
        private IEnumerable<int> GetDirectOnlyParentGroups(SecurityGroup group)
        {
            return group.ParentGroups
                .Select(g => g.Id)
                .ToArray();
        }
        private IEnumerable<int> GetDirectOnlyParentGroups(SecurityContext context, int userId)
        {
            return _cache.Groups.Values
                .Where(g => g.UserMemberIds.Contains(userId))
                .Select(g=>g.Id)
                .ToArray();
        }

    }
}
