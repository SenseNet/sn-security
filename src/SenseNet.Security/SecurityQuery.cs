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
        /// <param name="rootId">The Id of the focused entity.</param>
        /// <param name="handleBreaks">Controls the permission inheritance handling.</param>
        /// <returns>The IEnumerable&lt;SecurityEntity&gt; to further filtering.</returns>
        public IEnumerable<SecurityEntity> GetEntities(int rootId, BreakOptions handleBreaks = BreakOptions.Default)
        {
            SecurityEntity.EnterReadLock();
            try
            {
                var root = SecurityEntity.GetEntitySafe(_context, rootId, false);

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
        /// <param name="rootId">The Id of the focused entity.</param>
        /// <param name="handleBreaks">Controls the permission inheritance handling.</param>
        /// <returns>The IEnumerable&lt;SecurityEntity&gt; to further filtering.</returns>
        public IEnumerable<AceInfo> GetEntries(int rootId, BreakOptions handleBreaks = BreakOptions.Default)
        {
            return GetEntities(rootId, handleBreaks)
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries);
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
