using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using SenseNet.Diagnostics;
// ReSharper disable ArrangeStaticMemberQualifier

namespace SenseNet.Security
{
    /// <summary>
    /// Represents an entity that can be used to build a tree from and have security entries.
    /// </summary>
    [DebuggerDisplay("{" + nameof(ToString) + "()}")]
    public class SecurityEntity
    {
        // ReSharper disable once InconsistentNaming
        private static readonly ReaderWriterLockSlim __lock = new ReaderWriterLockSlim();
        internal static void EnterReadLock()
        {
            __lock.EnterReadLock();
        }
        internal static void ExitReadLock()
        {
            __lock.ExitReadLock();
        }
        private static void EnterWriteLock()
        {
            __lock.EnterWriteLock();
        }
        private static void ExitWriteLock()
        {
            __lock.ExitWriteLock();
        }

        /// <summary>
        /// Converts the information of this instance to its equivalent string representation.
        /// </summary>
        public override string ToString()
        {
            return
                $"Id: {Id}, parent: {Parent?.Id ?? 0}, owner: {OwnerId}, {(IsInherited ? "inherited" : "BREAKED")}";
        }

        /// <summary>
        /// Unique id of the entity.
        /// </summary>
        public int Id { get; internal set; }                           // 16
        /// <summary>
        /// Id of the owner user or group.
        /// </summary>
        public int OwnerId { get; internal set; }                      // 16
        /// <summary>
        /// Gets the inheritance state. True if the entity inherits the permission settings from its ancestors.
        /// </summary>
        public bool IsInherited { get; internal set; }                 //  1

        private readonly object _childrenSync = new object();

        internal List<SecurityEntity> Children { get; private set; }   // 32 * Count

        /// <summary>
        /// Parent of this entity or null.
        /// </summary>
        public SecurityEntity Parent { get; internal set; }

        /// <summary>
        /// Explicit permission entries. If this contains a value, it means this entity has explicit permission entries.
        /// Serves only test purposes, do not modify this object.
        /// </summary>
        public AclInfo Acl { get; private set; }

        internal void SetAclSafe(AclInfo acl)
        {
            if (acl == null)
            {
                // break dependency if exists
                if (Acl != null)
                    Acl.Entity = null;
            }
            else
            {
                // set dependency
                acl.Entity = this;
            }
            Acl = acl;
        }

        /// <summary>
        /// Gets the entity's level in the tree. It is the count of the items in the parent chain.
        /// </summary>
        public int Level
        {
            get
            {
                if (Parent == null)
                    return 0;
                return Parent.Level + 1;
            }
        }

        /// <summary>
        /// Used only by the initial loading process.
        /// </summary>
        [SuppressMessage("ReSharper", "InconsistentlySynchronizedField")]
        internal void AddChild_Unsafe(SecurityEntity child)
        {
            // This does not have to be thread safe as it is called only by the 
            // init process and has to be as fast as possible.
            if (Children == null)
                Children = new List<SecurityEntity>(new[] { child });
            else
                Children.Add(child);
        }
        internal void AddChild(SecurityEntity child) // called only from safe methods
        {
            lock (_childrenSync)
            {
                if (Children == null)
                {
                    Children = new List<SecurityEntity>(new[] {child});
                }
                else
                {
                    if (Children.Contains(child)) 
                        return;

                    // work with a temp list to maintain thread safety
                    var newList = new List<SecurityEntity>(Children) {child};

                    Children = newList;
                }
            }
        }
        internal void RemoveChild(SecurityEntity child) // called only from safe methods
        {
            lock (_childrenSync)
            {
                if (Children == null)
                    return;

                // work with a temp list to maintain thread safety
                var newList = new List<SecurityEntity>(Children);
                newList.Remove(child);

                Children = newList;
            }
        }

        /*************************************************************************  */
        /// <summary>
        /// True if this entity has explicit entries.
        /// </summary>
        public bool HasExplicitAcl => Acl != null;

        internal AclInfo GetFirstAcl()
        {
            var entity = this;
            while (entity != null && entity.Acl == null)
                entity = entity.Parent;
            return entity?.Acl;
        }
        [SuppressMessage("ReSharper", "ConvertIfStatementToReturnStatement")]
        internal int GetFirstAclId()
        {
            var entity = this;
            while (entity != null && entity.Acl == null)
                entity = entity.Parent;
            if (entity == null)
                return 0;
            return entity.Id;
        }

        /************************************************************************* Readers */
        internal static SecurityEntity GetEntity(SecurityContext ctx, int entityId, bool throwError)
        {
            EnterReadLock();
            try
            {
                return GetEntitySafe(ctx, entityId, throwError);
            }
            finally
            {
                ExitReadLock();
            }
        }
        /// <summary>
        /// Loads a security entity. If the entity cannot be found in the cache, it loads it
        /// from the database and puts it into the cache. It the entity cannot be loaded
        /// from the db either, a callback is made to the host application using the
        /// <see cref="SecurityContext.GetMissingEntity"/> method to compensate possible
        /// concurrency errors.
        /// </summary>
        /// <param name="ctx">The context to be used.</param>
        /// <param name="entityId">Id of the entity</param>
        /// <param name="throwError">Determines whether to throw an <see cref="EntityNotFoundException"/> if the entity was not found.</param>
        /// <returns>The security entity.</returns>
        internal static SecurityEntity GetEntitySafe(SecurityContext ctx, int entityId, bool throwError)
        {
            ctx.Cache.Entities.TryGetValue(entityId, out var entity);

            if (entity == null)
            {
                // compensation: try to load the entity and its aces from the db
                var storedEntity = DataHandler.GetStoredSecurityEntity(ctx.DataProvider, entityId);
                if (storedEntity != null)
                {
                    entity = CreateEntitySafe(ctx, entityId, storedEntity.ParentId, storedEntity.OwnerId, storedEntity.IsInherited, storedEntity.HasExplicitEntry);

                    var acl = new AclInfo(entityId);
                    var entries = ctx.DataProvider.LoadPermissionEntries(new[] { entityId });
                    foreach (var entry in entries)
                        acl.Entries.Add(new AceInfo { EntryType = entry.EntryType, IdentityId = entry.IdentityId, LocalOnly = entry.LocalOnly, AllowBits = entry.AllowBits, DenyBits = entry.DenyBits });
                    if (acl.Entries.Count > 0)
                        entity.SetAclSafe(acl);
                }
                else
                {
                    if (ctx.GetMissingEntity(entityId, out var parentId, out var ownerId))
                    {
                        DataHandler.CreateSecurityEntitySafe(ctx, entityId, parentId, ownerId);
                        entity = CreateEntitySafe(ctx, entityId, parentId, ownerId);
                    }
                }

                if (throwError && entity == null)
                    throw new EntityNotFoundException("Entity not found: " + entityId);
            }
            return entity;
        }

        internal static SecurityEntity[] PeekEntities(SecurityContext ctx, params int[] securityEntityIds)
        {
            EnterReadLock();
            try
            {
                return PeekEntitiesSafe(ctx, securityEntityIds);
            }
            finally
            {
                ExitReadLock();
            }
        }
        internal static SecurityEntity[] PeekEntitiesSafe(SecurityContext ctx, params int[] securityEntityIds)
        {
            var result = new SecurityEntity[securityEntityIds.Length];
            var entities = ctx.Cache.Entities;
            for (var i = 0; i < securityEntityIds.Length; i++)
                result[i] = entities.TryGetValue(securityEntityIds[i], out var entity) ? entity : null;
            return result;
        }

        internal static AccessControlList GetAccessControlList(SecurityContext ctx, int entityId, EntryType entryType = EntryType.Normal)
        {
            EnterReadLock();
            try
            {
                var entity = SecurityEntity.GetEntitySafe(ctx, entityId, true);
                var aclInfo = GetFirstAclSafe(ctx, entityId, false);
                return aclInfo == null
                    ? AclInfo.CreateEmptyAccessControlList(entityId, entity.IsInherited)
                    : aclInfo.ToAccessContolList(entityId, entryType);
            }
            finally
            {
                ExitReadLock();
            }
        }

        internal static AclInfo GetAclInfoCopy(SecurityContext ctx, int entityId, EntryType? entryType = null)
        {
            var entity = GetEntitySafe(ctx, entityId, false);
            var acl = entity?.Acl;
            return acl == null ? null : entity.Acl.Copy(entryType);
        }

        //---- todo

        internal static AclInfo GetFirstAcl(SecurityContext ctx, int entityId, bool throwError)
        {
            EnterReadLock();
            try
            {
                return GetFirstAclSafe(ctx, entityId, throwError);
            }
            finally
            {
                ExitReadLock();
            }
        }
        internal static AclInfo GetFirstAclSafe(SecurityContext ctx, int entityId, bool throwError)
        {
            var entity = GetEntitySafe(ctx, entityId, throwError);
            return entity?.GetFirstAcl();
        }
        internal static int GetFirstAclId(SecurityContext ctx, int entityId)
        {
            var acl = GetFirstAcl(ctx, entityId, false);
            return acl?.Entity.Id ?? 0;
        }

        /// <summary>
        /// Collects all entity ids in a subtree, including the root entity's.
        /// </summary>
        internal static void CollectEntityIds(SecurityEntity rootEntity, List<int> entityIds)
        {
            if (rootEntity == null)
                return;

            entityIds.Add(rootEntity.Id);

            if (rootEntity.Children == null)
                return;

            foreach (var child in rootEntity.Children)
            {
                CollectEntityIds(child, entityIds);
            }
        }

        /************************************************************************* Writers */

        internal static void BreakInheritance(SecurityContext ctx, IEnumerable<int> entityIds)
        {
            EnterWriteLock();
            try
            {
                foreach (var entityId in entityIds)
                    BreakInheritanceSafe(ctx, entityId);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        internal static void BreakInheritance(SecurityContext ctx, int entityId)
        {
            EnterWriteLock();
            try
            {
                BreakInheritanceSafe(ctx, entityId);
            }
            finally
            {
                ExitWriteLock();
            }

        }
        internal static void BreakInheritanceSafe(SecurityContext ctx, int entityId)
        {
            var entity = GetEntitySafe(ctx, entityId, false);
            if (entity == null)
                return;

            entity.IsInherited = false;

            if (entity.Acl == null)
            {
                // creating an empty broken acl
                entity.SetAclSafe(new AclInfo(entityId));
            }
        }

        internal static void UnbreakInheritance(SecurityContext ctx, IEnumerable<int> entityIds)
        {
            EnterWriteLock();
            try
            {
                foreach (var entityId in entityIds)
                    UnbreakInheritanceSafe(ctx, entityId);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        internal static void UnbreakInheritance(SecurityContext ctx, int entityId)
        {
            EnterWriteLock();
            try
            {
                UnbreakInheritanceSafe(ctx, entityId);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        internal static void UnbreakInheritanceSafe(SecurityContext ctx, int entityId)
        {
            var entity = GetEntitySafe(ctx, entityId, false);
            if (entity == null)
                return;

            entity.IsInherited = true;

            var acl = entity.Acl;
            if (acl != null && acl.Entries.Count == 0)
                entity.SetAclSafe(null);
        }

        internal static SecurityEntity CreateEntity(SecurityContext ctx, int entityId, int parentEntityId, int ownerId, bool? isInherited = null, bool? hasExplicitEntry = null)
        {
            EnterWriteLock();
            try
            {
                return CreateEntitySafe(ctx, entityId, parentEntityId, ownerId, isInherited, hasExplicitEntry);
            }
            finally
            {
                ExitWriteLock();
            }

        }
        internal static SecurityEntity CreateEntitySafe(SecurityContext ctx, int entityId, int parentEntityId, int ownerId, bool? isInherited = null, bool? hasExplicitEntry = null)
        {
            SecurityEntity parent = null;
            if (parentEntityId != default)
            {
                // if the parent cannot be loaded (even from the db), this will throw an exception
                parent = GetEntitySafe(ctx, parentEntityId, true);
            }

            var entity = new SecurityEntity
            {
                Id = entityId,
                IsInherited = isInherited ?? true,
                OwnerId = ownerId,
                Parent = parent
            };
            parent?.AddChild(entity);
            ctx.Cache.Entities[entityId] = entity;

            return entity;
        }

        internal static void ModifyEntityOwner(SecurityContext ctx, int entityId, int ownerId)
        {
            EnterWriteLock();
            try
            {
                var entity = GetEntitySafe(ctx, entityId, true);
                entity.OwnerId = ownerId;
            }
            finally
            {
                ExitWriteLock();
            }
        }

        internal static void DeleteEntity(SecurityContext ctx, int entityId)
        {
            EnterWriteLock();
            try
            {
                var entity = GetEntitySafe(ctx, entityId, false);
                if (entity == null)
                    return;
                DeleteEntityRecursiveSafe(ctx, entity);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        private static void DeleteEntityRecursiveSafe(SecurityContext ctx, SecurityEntity entity)
        {
            var children = entity.Children;
            if (children != null)
                foreach (var child in children.ToArray())
                    DeleteEntityRecursiveSafe(ctx, child);

            entity.Parent?.RemoveChild(entity);

            entity.SetAclSafe(null);

            ctx.Cache.Entities.Remove(entity.Id);
        }

        internal static void MoveEntity(SecurityContext ctx, int sourceEntityId, int targetEntityId)
        {
            EnterWriteLock();
            try
            {
                var source = GetEntitySafe(ctx, sourceEntityId, false);
                var target = GetEntitySafe(ctx, targetEntityId, false);
                if (source == null || target == null)
                    return;

                source.Parent.RemoveChild(source);
                source.Parent = target;
                source.Parent.AddChild(source);
            }
            finally
            {
                ExitWriteLock();
            }
        }

        internal static void RemoveAcls(SecurityContext ctx, IEnumerable<int> entityIds)
        {
            EnterWriteLock();
            try
            {
                RemoveAclsSafe(ctx, entityIds);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        private static void RemoveAclsSafe(SecurityContext ctx, IEnumerable<int> entityIds)
        {
            foreach (var entityId in entityIds)
            {
                var entity = GetEntitySafe(ctx, entityId, false);
                entity?.SetAclSafe(null);
            }
        }

        internal static void ApplyAclEditing(SecurityContext ctx, AclInfo[] aclsToSet,
            IEnumerable<int> breaks, IEnumerable<int> unbreaks,
            List<StoredAce> entriesToRemove, List<int> emptyAcls)
        {
            EnterWriteLock();
            try
            {
                var breakedIdArray = breaks as int[] ?? breaks.ToArray();
                var unbreakedIdArray = unbreaks as int[] ?? unbreaks.ToArray();
                using (var op = SnTrace.Security.StartOperation("ApplyAcl started."))
                {
                    foreach (var aclInfo in aclsToSet)
                        SetAclSafe(ctx, aclInfo);
                    foreach (var entityId in breakedIdArray)
                        BreakInheritanceSafe(ctx, entityId);
                    foreach (var entityId in unbreakedIdArray)
                        UnbreakInheritanceSafe(ctx, entityId);

                    RemoveEntriesSafe(ctx, entriesToRemove);

                    var aclsToRemove = emptyAcls.Where(x => x != default && ctx.Cache.Entities[x].IsInherited).ToArray();
                    SecurityEntity.RemoveAclsSafe(ctx, aclsToRemove);

                    op.Successful = true;
                }

                if (SnTrace.Security.Enabled)
                    SnTrace.Security.Write("ApplyAcl finished. SetAcl: {0}, Break: {1}, Unbreak: {2}, Remove: {3}, Empty: {4}",
                        aclsToSet.Length > 0 ? aclsToSet.Length + " (" + aclsToSet[0] + ")" : "0",
                        breakedIdArray.Length, unbreakedIdArray.Length, entriesToRemove.Count, emptyAcls.Count);
            }
            finally
            {
                ExitWriteLock();
            }
        }

        private static void RemoveEntriesSafe(SecurityContext ctx, IEnumerable<StoredAce> entries)
        {
            foreach (var entry in entries)
            {
                // get entity without error
                var entity = GetEntitySafe(ctx, entry.EntityId, false);

                // get acl if exists
                var acl = entity?.Acl;

                // get related entry if exists
                var aclEntries = acl?.Entries;
                var entryToRemove = aclEntries?.FirstOrDefault(e => e.EntryType == entry.EntryType && e.IdentityId == entry.IdentityId && e.LocalOnly == entry.LocalOnly);
                if(entryToRemove == null)
                    continue;

                // remove the entry
                aclEntries.Remove(entryToRemove);

                // remove acl if it gets empty and there is no break on the entity
                if (aclEntries.Count == 0 && entity.IsInherited)
                    entity.SetAclSafe(null);
            }
        }

        private static void SetAclSafe(SecurityContext ctx, AclInfo aclInfo)
        {
            var entity = SecurityEntity.GetEntitySafe(ctx, aclInfo.EntityId, false);
            if (entity == null)
            {
                SnTrace.Security.WriteError("Entity in AclInfo not found: {0}", aclInfo.EntityId);
                return;
            }
            var origAcl = entity.Acl;
            if (origAcl != null)
            {
                // merge ACLs
                foreach (var newAce in aclInfo.Entries)
                {
                    var origAce = origAcl.Entries.FirstOrDefault(x => x.EntryType == newAce.EntryType && x.IdentityId == newAce.IdentityId && x.LocalOnly == newAce.LocalOnly);
                    if (origAce != null)
                    {
                        origAce.AllowBits = newAce.AllowBits;
                        origAce.DenyBits = newAce.DenyBits;
                        if ((origAce.AllowBits | origAce.DenyBits) == 0)
                            origAcl.Entries.Remove(origAce);
                    }
                    else
                    {
                        if ((newAce.AllowBits | newAce.DenyBits) != 0)
                            origAcl.Entries.Add(newAce);
                    }

                }
                if (origAcl.Inherits && origAcl.Entries.Count == 0)
                {
                    entity.SetAclSafe(null);
                }
            }
            else
            {
                // brand new acl
                entity.SetAclSafe(aclInfo);
            }
        }

        // for new membership API

        internal static void RemoveIdentityRelatedAces(SecurityContext ctx, int identityId)
        {
            EnterWriteLock();
            try
            {
                RemoveIdentityRelatedAcesSafe(ctx, identityId);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        internal static void RemoveIdentityRelatedAcesSafe(SecurityContext ctx, int identityId)
        {
            foreach (var entity in ctx.Cache.Entities.Values)
            {
                var acl = entity.Acl;
                if (acl == null)
                    continue;
                var entries = acl.Entries;
                var acesToRemove = entries.Where(e => e.IdentityId == identityId).ToArray();
                foreach (var aceToRemove in acesToRemove)
                    entries.Remove(aceToRemove);
                if (entries.Count == 0)
                    entity.SetAclSafe(null);
            }
        }

    }
}
