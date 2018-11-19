using System;
using System.Collections.Generic;
using System.Linq;
// ReSharper disable ArrangeThisQualifier

namespace SenseNet.Security
{
    /// <summary>
    /// Controls the inheritance handling in the collection enumerators.
    /// </summary>
    [Flags]
    public enum BreakOptions
    {
        /// <summary>Indicates that the tree walker does not take into account any inheritance break.</summary>
        Default = 0,
        /// <summary>Indicates that the parent chain walker stops at any inheritance break.</summary>
        StopAtParentBreak = 1,
        /// <summary>Indicates that the subtree walker do not enter into the broken inheritance subtrees.</summary>
        StopAtSubtreeBreaks = 2
    }

    /// <summary>
    /// Contains security-related queryable collections.
    /// </summary>
    public class SecurityQuery
    {
        private enum Axis { All, ParentChain, Subtree };

        /* ============================================================ Static part */

        /// <summary>
        /// Returns SecurityQuery instance that supports any query on the parent chain
        /// and the subtree of a later specified entity.
        /// </summary>
        public static SecurityQuery All(SecurityContext context)
        {
            return new SecurityQuery(context, Axis.All);
        }

        /// <summary>
        /// Returns SecurityQuery instance that supports any query on the parent chain of a later specified entity.
        /// Note that the focused entity is not a member of its parent chain.
        /// </summary>
        public static SecurityQuery ParentChain(SecurityContext context)
        {
            return new SecurityQuery(context, Axis.ParentChain);
        }

        /// <summary>
        /// Returns SecurityQuery instance that supports any query in the subtree of a later specified entity.
        /// Note that the focused entity is a member of its subtree.
        /// </summary>
        public static SecurityQuery Subtree(SecurityContext context)
        {
            return new SecurityQuery(context, Axis.Subtree);
        }

        /* ============================================================ Instance part */

        private SecurityQuery(SecurityContext context, Axis axis)
        {
            _context = context;
            _axis = axis;
        }
        private readonly SecurityContext _context;
        private readonly Axis _axis;

        /// <summary>
        /// Returns all entities in the predefined axis (All, ParentChain, Subtree) of the specified entity.
        /// The collection is empty if the entity was not found.
        /// This operation is thread safe. The thread safety uses system resources, so to minimize these,
        /// it's strongly recommended processing as fast as possible.
        /// </summary>
        /// <param name="entityId">The Id of the focused entity.</param>
        /// <param name="handleBreaks">Controls the permission inheritance handling.</param>
        /// <returns>The IEnumerable&lt;SecurityEntity&gt; to further filtering.</returns>
        public IEnumerable<SecurityEntity> GetEntities(int entityId, BreakOptions handleBreaks = BreakOptions.Default)
        {
            SecurityEntity.EnterReadLock();
            try
            {
                var root = SecurityEntity.GetEntitySafe(_context, entityId, false);

                IEnumerable<SecurityEntity> collection;
                switch (_axis)
                {
                    case Axis.All:
                        collection = GetEntitiesFromParentChain(root, handleBreaks)
                            .Union(GetEntitiesFromSubtree(root, handleBreaks));
                        break;
                    case Axis.ParentChain:
                        collection = GetEntitiesFromParentChain(root, handleBreaks);
                        break;
                    case Axis.Subtree:
                        collection = GetEntitiesFromSubtree(root, handleBreaks);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException("Unknown axis: " + _axis);
                }

                foreach (var entity in collection)
                    yield return entity;
            }
            finally
            {
                SecurityEntity.ExitReadLock();
            }
        }
        /// <summary>
        /// Returns all entries in the predefined axis (All, ParentChain, Subtree) of the specified entity.
        /// The collection is empty if the entity was not found.
        /// Note that the output entries do not refers their owher entities and there is no inexpensive way 
        /// to recover them.
        /// This operation is thread safe. The thread safety uses system resources, so to minimize these,
        /// it's strongly recommended processing as fast as possible.
        /// </summary>
        /// <param name="entityId">The Id of the focused entity.</param>
        /// <param name="handleBreaks">Controls the permission inheritance handling.</param>
        /// <returns>The IEnumerable&lt;SecurityEntity&gt; to further filtering.</returns>
        public IEnumerable<AceInfo> GetEntries(int entityId, BreakOptions handleBreaks = BreakOptions.Default)
        {
            return GetEntities(entityId, handleBreaks)
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries);
        }

        /// <summary>
        /// Returns permission changes in the predefined axis (All, ParentChain, Subtree) of the specified entity.
        /// A permission is changed when the parent permission and local permission are not equal.
        /// The collection can be prefiltered with a relatedIdentity parameter.
        /// This operation is thread safe. The thread safety uses system resources, so to minimize these,
        /// it's strongly recommended processing as fast as possible.
        /// </summary>
        /// <param name="entityId">The Id of the focused entity.</param>
        /// <param name="relatedIdentities">Identity filter. Null or empty means inactive filter.</param>
        /// <param name="handleBreaks">Controls the permission inheritance handling.</param>
        /// <returns>The IEnumerable&lt;PermissionChange&gt; to further filtering.</returns>
        public IEnumerable<PermissionChange> GetPermissionChanges(int entityId, IEnumerable<int> relatedIdentities,
            BreakOptions handleBreaks = BreakOptions.Default)
        {
            var identities = relatedIdentities?.ToArray();
            var isIdentityFilterActive = identities != null && identities.Length > 0;

            foreach (var entity in GetEntities(entityId, handleBreaks))
            {
                if (entity.Acl == null)
                    continue;

                if (entity.IsInherited)
                {
                    foreach (var entry in entity.Acl.Entries)
                    {
                        // skip local only if this is not the root
                        if (entity.Id != entityId || !entry.LocalOnly)
                            // filter by related identities
                            if (!isIdentityFilterActive || identities.Contains(entry.IdentityId))
                                yield return new PermissionChange(entity, entry);
                    }
                }
                else
                {
                    var effectiveEntries = _context.Evaluator.GetEffectiveEntriesSafe(entity.Parent.Id, identities);

                    var localEntries = entity.Acl.Entries
                        .Where(e => (entity.Id != entityId || !e.LocalOnly) &&
                                    // ReSharper disable once AssignNullToNotNullAttribute
                                    (!isIdentityFilterActive || identities.Contains(e.IdentityId)))
                        .ToList();

                    // Aggregate effective and local bits per identity
                    foreach (var effectiveEntry in effectiveEntries)
                    {
                        var localEntry = localEntries.FirstOrDefault(e =>
                            e.IdentityId == effectiveEntry.IdentityId && e.EntryType == effectiveEntry.EntryType);

                        var aggregatedBits = new PermissionBitMask
                        {
                            AllowBits = effectiveEntry.AllowBits,
                            DenyBits = effectiveEntry.DenyBits
                        };

                        if (localEntry != null)
                        {
                            aggregatedBits.AllowBits |= localEntry.AllowBits;
                            aggregatedBits.DenyBits |= localEntry.DenyBits;
                            // Remove processed item from local entries.
                            localEntries.Remove(localEntry);
                        }

                        yield return new PermissionChange
                        (
                             entity,
                             effectiveEntry.IdentityId,
                             effectiveEntry.EntryType,
                             aggregatedBits
                        );
                    }

                    // New local entries that are not exist in parent's effective ACEs
                    foreach (var localEntry in localEntries)
                        yield return new PermissionChange(entity,localEntry);
                }
            }
        }

        private IEnumerable<SecurityEntity> GetEntitiesFromParentChain(SecurityEntity entity, BreakOptions handleBreaks)
        {
            if ((handleBreaks & BreakOptions.StopAtParentBreak) != 0)
            {
                while ((entity = entity?.Parent) != null)
                {
                    yield return entity;
                    if (!entity.IsInherited)
                        yield break;
                }
            }
            else
            {
                while ((entity = entity?.Parent) != null)
                    yield return entity;
            }
        }

        private IEnumerable<SecurityEntity> GetEntitiesFromSubtree(SecurityEntity root, BreakOptions handleBreaks)
        {
            return root == null
                ? Enumerable.Empty<SecurityEntity>()
                : (handleBreaks & BreakOptions.StopAtSubtreeBreaks) != 0
                    ? new StopAtBreaksEntityTreeWalker(root)
                    : (IEnumerable<SecurityEntity>)new EntityTreeWalker(root);
        }
    }
}
