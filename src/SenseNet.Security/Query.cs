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
        StopAtParentBreaks = 1,
        StopAtSubtreeBreaks = 2
    }

    public class Query
    {
        public SecurityContext Context { get; }

        public Query(SecurityContext context)
        {
            this.Context = context;
        }
        public IEnumerable<SecurityEntity> GetEntities(int rootId, BreakOptions handleBreaks = BreakOptions.Default)
        {
            SecurityEntity.EnterReadLock();
            try
            {
                var root = SecurityEntity.GetEntitySafe(Context, rootId, false);
                return ParentChain.GetEntities(root, handleBreaks).Union(Subtree.GetEntities(root, handleBreaks));
            }
            finally
            {
                SecurityEntity.ExitReadLock();
            }
        }

        public class ParentChain
        {
            public SecurityContext Context { get; }
            public ParentChain(SecurityContext context)
            {
                this.Context = context;
            }

            public IEnumerable<SecurityEntity> GetEntities(int rootId, BreakOptions handleBreaks = BreakOptions.Default)
            {
                SecurityEntity.EnterReadLock();
                try
                {
                    var root = SecurityEntity.GetEntitySafe(Context, rootId, false);
                    foreach (var entity in GetEntities(root, handleBreaks))
                        yield return entity;
                }
                finally
                {
                    SecurityEntity.ExitReadLock();
                }
            }

            internal static IEnumerable<SecurityEntity> GetEntities(SecurityEntity entity, BreakOptions handleBreaks)
            {
                if ((handleBreaks & BreakOptions.StopAtParentBreaks) != 0)
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
        }

        public class Subtree
        {
            public SecurityContext Context { get; }
            public Subtree(SecurityContext context)
            {
                this.Context = context;
            }

            public IEnumerable<SecurityEntity> GetEntities(int rootId, BreakOptions handleBreaks = BreakOptions.Default)
            {
                SecurityEntity.EnterReadLock();
                try
                {
                    var root = SecurityEntity.GetEntitySafe(Context, rootId, false);
                    foreach (var entity in GetEntities(root, handleBreaks))
                        yield return entity;
                }
                finally
                {
                    SecurityEntity.ExitReadLock();
                }
            }

            internal static IEnumerable<SecurityEntity> GetEntities(SecurityEntity root, BreakOptions handleBreaks)
            {
                return root == null
                    ? Enumerable.Empty<SecurityEntity>()
                    : (handleBreaks & BreakOptions.StopAtSubtreeBreaks) != 0
                            ? new StopAtBreaksEntityTreeWalker(root)
                            : (IEnumerable<SecurityEntity>)new EntityTreeWalker(root); 
            }
        }
    }
}
