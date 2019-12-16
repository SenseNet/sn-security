using System;
using System.Collections.Generic;
using System.Linq;

namespace SenseNet.Security
{
    /// <summary>
    /// Contains an internal API for querying permission values in the system by entities, identities or permission types.
    /// </summary>
    internal class PermissionQuery
    {
        public static Dictionary<PermissionTypeBase, int> GetExplicitPermissionsInSubtree(SecurityContext context, int entityId, int[] identities, bool includeRoot)
        {
            SecurityEntity.EnterReadLock();
            try
            {
                var counters = new int[PermissionTypeBase.PermissionCount];

                var root = SecurityEntity.GetEntitySafe(context, entityId, true);
                foreach (var entity in new EntityTreeWalker(root))
                {
                    // step forward if there is no any setting
                    if (!entity.HasExplicitAcl || (entity.Id == entityId && !includeRoot))
                        continue;

                    // if breaked, adding existing parent-s effective identities because all identities are related.
                    var localBits = new PermissionBitMask();
                    if (!entity.IsInherited && entity.Parent != null && (includeRoot || entity.Parent.Id != entityId))
                        CollectPermissionsFromLocalAces(context.Evaluator.GetEffectiveEntriesSafe(entity.Parent.Id, identities, EntryType.Normal), localBits);

                    // adding explicite identities
                    CollectPermissionsFromAces(context.Evaluator.GetExplicitEntriesSafe(entity.Id, identities, EntryType.Normal), PermissionLevel.AllowedOrDenied, counters, localBits);
                }

                var result = new Dictionary<PermissionTypeBase, int>();
                for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                    result.Add(PermissionTypeBase.GetPermissionTypeByIndex(i), counters[i]);

                return result;
            }
            finally
            {
                SecurityEntity.ExitReadLock();
            }
        }

        /******************************************************************************************************* Related Identities */

        public static IEnumerable<int> GetRelatedIdentities(SecurityContext context, int entityId, PermissionLevel level)
        {
            var identities = new List<int>();
            SecurityEntity.EnterReadLock();
            try
            {
                var root = SecurityEntity.GetEntitySafe(context, entityId, true);
                foreach (var entity in new EntityTreeWalker(root))
                {
                    // step forward if there is no any setting
                    if (!entity.HasExplicitAcl)
                        continue;

                    // if breaked, adding existing parent-s effective identities because all identities are related.
                    if (!entity.IsInherited && entity.Parent != null)
                        CollectIdentitiesFromAces(context.Evaluator.GetEffectiveEntriesSafe(entity.Parent.Id, null, EntryType.Normal), level, identities);

                    // adding explicite identities
                    CollectIdentitiesFromAces(context.Evaluator.GetExplicitEntriesSafe(entity.Id, null, EntryType.Normal), level, identities);
                }
            }
            finally
            {
                SecurityEntity.ExitReadLock();
            }
            return identities;
        }
        private static void CollectIdentitiesFromAces(List<AceInfo> aces, PermissionLevel level, List<int> identities)
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

        public static Dictionary<PermissionTypeBase, int> GetRelatedPermissions(SecurityContext context, int entityId, PermissionLevel level, bool explicitOnly, int identityId, Func<int, bool> isEnabled)
        {
            if (!explicitOnly)
                throw new NotSupportedException("Not supported in this version. Use explicitOnly = true");

            SecurityEntity.EnterReadLock();
            try
            {
                var counters = new int[PermissionTypeBase.PermissionCount];

                var identities = new[] { identityId };

                var root = SecurityEntity.GetEntitySafe(context, entityId, true);
                foreach (var entity in new EntityTreeWalker(root))
                {
                    // step forward if there is no any setting
                    if (!entity.HasExplicitAcl)
                        continue;

                    if (!isEnabled(entity.Id))
                        continue;

                    // if breaked, adding existing parent-s effective identities because all identities are related.
                    var localBits = new PermissionBitMask();
                    if (!entity.IsInherited && entity.Parent != null)
                        CollectPermissionsFromLocalAces(context.Evaluator.GetEffectiveEntriesSafe(entity.Parent.Id, identities, EntryType.Normal), localBits);

                    // adding explicite identities
                    CollectPermissionsFromAces(context.Evaluator.GetExplicitEntriesSafe(entity.Id, identities, EntryType.Normal), level, counters, localBits);
                }

                var result = new Dictionary<PermissionTypeBase, int>();
                for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                    result.Add(PermissionTypeBase.GetPermissionTypeByIndex(i), counters[i]);

                return result;
            }
            finally
            {
                SecurityEntity.ExitReadLock();
            }
        }
        private static void CollectPermissionsFromLocalAces(List<AceInfo> aces, PermissionBitMask localBits)
        {
            foreach (var ace in aces)
            {
                localBits.AllowBits |= ace.AllowBits;
                localBits.DenyBits |= ace.DenyBits;
            }
        }
        private static void CollectPermissionsFromAces(List<AceInfo> aces, PermissionLevel level, int[] counters, PermissionBitMask localBits)
        {
            // Aggregate aces and switch of the 'used bits' in the local only permission bit set.
            foreach (var ace in aces)
            {
                SetPermissionsCountersByPermissionLevel(counters, level, ace.AllowBits, ace.DenyBits);
                localBits.AllowBits &= ~ace.AllowBits;
                localBits.DenyBits &= ~ace.DenyBits ;
            }
            // Finally play the rest bits (all breaked bits are switched in that is not used in any explicit entry)
            SetPermissionsCountersByPermissionLevel(counters, level, localBits.AllowBits, localBits.DenyBits);
        }
        private static void SetPermissionsCountersByPermissionLevel(int[] counters, PermissionLevel level, ulong allowBits, ulong denyBits)
        {
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
                default:
                    break;
            }
        }
        private static void IncrementCounters(ulong bits, int[] counters)
        {
            var mask = 1uL;
            var b = bits;
            foreach (var pt in PermissionTypeBase.GetPermissionTypes())
            {
                if ((b & mask) > 0)
                    counters[pt.Index]++;
                mask = mask << 1;
            }
        }

        /********************************************************************************************************* Related Entities */

        public static IEnumerable<int> GetRelatedEntities(SecurityContext context, int entityId, PermissionLevel level, bool explicitOnly, int identityId, IEnumerable<PermissionTypeBase> permissionTypes)
        {
            if (!explicitOnly)
                throw new NotSupportedException("Not supported in this version. Use explicitOnly = true");

            SecurityEntity.EnterReadLock();
            try
            {
                var entityIds = new List<int>();

                var mask = PermissionTypeBase.GetPermissionMask(permissionTypes);
                var identities = new[] { identityId };

                var root = SecurityEntity.GetEntitySafe(context, entityId, true);
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

                    // adding explicite identities
                    if (!added)
                        if (HasBitsByExpliciteAces(context.Evaluator.GetExplicitEntriesSafe(entity.Id, identities, EntryType.Normal), level, mask))
                            entityIds.Add(entity.Id);
                }

                return entityIds;
            }
            finally
            {
                SecurityEntity.ExitReadLock();
            }

        }
        private static bool HasBitsByEffectiveAces(List<AceInfo> aces, PermissionLevel level, ulong mask)
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
        private static bool HasBitsByExpliciteAces(List<AceInfo> aces, PermissionLevel level, ulong mask)
        {
            var permBits = new PermissionBitMask();
            foreach (var ace in aces)
            {
                    permBits.AllowBits |= ace.AllowBits;
                    permBits.DenyBits |= ace.DenyBits;
            }
            return HasBits(permBits, level, mask);
        }
        private static bool HasBits(PermissionBitMask permBits, PermissionLevel level, ulong permissionMask)
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

        public static IEnumerable<int> GetRelatedIdentities(SecurityContext context, int entityId, PermissionLevel level, IEnumerable<PermissionTypeBase> permissionTypes)
        {
            SecurityEntity.EnterReadLock();
            try
            {
                var identities = new List<int>();
                var mask = PermissionTypeBase.GetPermissionMask(permissionTypes);
                var root = SecurityEntity.GetEntitySafe(context, entityId, true);
                foreach (var entity in new EntityTreeWalker(root))
                {
                    // step forward if there is no any setting
                    if (!entity.HasExplicitAcl)
                        continue;

                    // if breaked, adding existing parent-s effective identities because all identities are related.
                    if (!entity.IsInherited && entity.Parent != null)
                        CollectIdentitiesFromAces(context.Evaluator.GetEffectiveEntriesSafe(entity.Parent.Id, null, EntryType.Normal), level, mask, identities);

                    // adding explicite identities
                    CollectIdentitiesFromAces(context.Evaluator.GetExplicitEntriesSafe(entity.Id, null, EntryType.Normal), level, mask, identities);
                }
                return identities;
            }
            finally
            {
                SecurityEntity.ExitReadLock();
            }
        }
        private static void CollectIdentitiesFromAces(List<AceInfo> aces, PermissionLevel level, ulong mask, List<int> identities)
        {
            foreach (var ace in aces)
                if (!identities.Contains(ace.IdentityId))
                    if(HasBits(ace.AllowBits, ace.DenyBits, level, mask))
                        if(!identities.Contains(ace.IdentityId))
                            identities.Add(ace.IdentityId);
        }
        private static bool HasBits(ulong allowBits, ulong denyBits, PermissionLevel level, ulong permissionMask)
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

        public static IEnumerable<int> GetRelatedEntitiesOneLevel(SecurityContext context, int entityId, PermissionLevel level, int identityId, IEnumerable<PermissionTypeBase> permissionTypes)
        {
            SecurityEntity.EnterReadLock();
            try
            {
                var result = new List<int>();
                var identities = new[] { identityId };
                var mask = PermissionTypeBase.GetPermissionMask(permissionTypes);
                var root = SecurityEntity.GetEntitySafe(context, entityId, true);
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
                SecurityEntity.ExitReadLock();
            }
        }

        /********************************************************************************************* Allowed Users */

        public static IEnumerable<int> GetAllowedUsers(SecurityContext context, int entityId, IEnumerable<PermissionTypeBase> permissions)
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
        private static IEnumerable<int> GetFlattenedUsers(SecurityContext context, IEnumerable<int> identities)
        {
            var flattenedUsers = new List<int>();

            var groups = new List<SecurityGroup>();
            foreach (var identity in identities.Distinct())
            {
                if (context.Cache.Groups.TryGetValue(identity, out var group))
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
                var allUsersInGroup = context.Cache.GetAllUsersInGroup(group);
                foreach (var userId in allUsersInGroup)
                {
                    if (!flattenedUsers.Contains(userId))
                        flattenedUsers.Add(userId);
                }
            }
            return flattenedUsers;
        }

        /********************************************************************************************* Parent Groups */

        public static IEnumerable<int> GetParentGroups(SecurityContext context, int identityId, bool directOnly)
        {
            if (context.Cache.Groups.TryGetValue(identityId, out var group))
                return directOnly ? GetDirectOnlyParentGroups(group) : GetAllParentGroups(context, group);
            return directOnly ? GetDirectOnlyParentGroups(context, identityId) : GetAllParentGroups(context, identityId);
        }
        private static IEnumerable<int> GetAllParentGroups(SecurityContext context, SecurityGroup group)
        {
            return context.Cache.GetAllParentGroupIds(group);
        }
        private static IEnumerable<int> GetAllParentGroups(SecurityContext context, int userId)
        {
            if (context.Cache.Membership.TryGetValue(userId, out var groupIds))
                return groupIds;
            return new int[0];
        }
        private static IEnumerable<int> GetDirectOnlyParentGroups(SecurityGroup group)
        {
            return group.ParentGroups
                .Select(g => g.Id)
                .ToArray();
        }
        private static IEnumerable<int> GetDirectOnlyParentGroups(SecurityContext context, int userId)
        {
            return context.Cache.Groups.Values
                .Where(g => g.UserMemberIds.Contains(userId))
                .Select(g=>g.Id)
                .ToArray();
        }

    }
}
