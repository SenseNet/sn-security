using System;
using System.Collections.Generic;
using System.Linq;
// ReSharper disable ArrangeThisQualifier

namespace SenseNet.Security
{
    [Flags]
    public enum BreakOptions
    {
        Default = 0,
        StopAtParentBreak = 1,
        StopAtSubtreeBreaks = 2
    }

    public class SecurityQuery
    {
        private enum Axis { All, ParentChain, Subtree };

        /* ============================================================ Static part */

        public static SecurityQuery All(SecurityContext context)
        {
            return new SecurityQuery(context, Axis.All);
        }

        public static SecurityQuery ParentChain(SecurityContext context)
        {
            return new SecurityQuery(context, Axis.ParentChain);
        }

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
        private SecurityContext _context;
        private Axis _axis;

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
