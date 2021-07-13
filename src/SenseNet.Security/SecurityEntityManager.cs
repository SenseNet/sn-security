using System.Collections.Generic;
using System.Linq;
using System.Threading;
using SenseNet.Diagnostics;

namespace SenseNet.Security
{
    /// <summary>
    /// Manages SecurityEntity tree (designed for internal singleton service).
    /// </summary>
    internal class SecurityEntityManager
    {
        private readonly IMissingEntityHandler _missingEntityHandler;
        private readonly ISecurityDataProvider _dataProvider;
        private readonly SecurityCache _cache;

        public SecurityEntityManager(ISecurityDataProvider dataProvider, SecurityCache cache, IMissingEntityHandler missingEntityHandler)
        {
            _missingEntityHandler = missingEntityHandler;
            _dataProvider = dataProvider;
            _cache = cache;
        }

        // ReSharper disable once InconsistentNaming
        private readonly ReaderWriterLockSlim __lock = new ReaderWriterLockSlim();

        internal void EnterReadLock()
        {
            __lock.EnterReadLock();
        }
        internal void ExitReadLock()
        {
            __lock.ExitReadLock();
        }
        private void EnterWriteLock()
        {
            __lock.EnterWriteLock();
        }
        private void ExitWriteLock()
        {
            __lock.ExitWriteLock();
        }

        /************************************************************************* Readers */

        internal SecurityEntity GetEntity(int entityId, bool throwError)
        {
            EnterReadLock();
            try
            {
                return GetEntitySafe(entityId, throwError);
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
        /// <see cref="IMissingEntityHandler.GetMissingEntity"/> method to compensate possible
        /// concurrency errors.
        /// </summary>
        /// <param name="ctx">The context to be used.</param>
        /// <param name="entityId">Id of the entity</param>
        /// <param name="throwError">Determines whether to throw an <see cref="EntityNotFoundException"/> if the entity was not found.</param>
        /// <returns>The security entity.</returns>
        internal SecurityEntity GetEntitySafe(int entityId, bool throwError)
        {
            _cache.Entities.TryGetValue(entityId, out var entity);

            if (entity == null)
            {
                var dataHandler = SecuritySystem.Instance.DataHandler;

                // compensation: try to load the entity and its aces from the db
                var storedEntity = dataHandler.GetStoredSecurityEntity(_dataProvider, entityId);
                if (storedEntity != null)
                {
                    entity = CreateEntitySafe(entityId, storedEntity.ParentId, storedEntity.OwnerId, storedEntity.IsInherited, storedEntity.HasExplicitEntry);

                    var acl = new AclInfo(entityId);
                    var entries = _dataProvider.LoadPermissionEntries(new[] { entityId });
                    foreach (var entry in entries)
                        acl.Entries.Add(new AceInfo { EntryType = entry.EntryType, IdentityId = entry.IdentityId, LocalOnly = entry.LocalOnly, AllowBits = entry.AllowBits, DenyBits = entry.DenyBits });
                    if (acl.Entries.Count > 0)
                        entity.SetAclSafe(acl);
                }
                else
                {
                    if (_missingEntityHandler.GetMissingEntity(entityId, out var parentId, out var ownerId))
                    {
                        dataHandler.CreateSecurityEntitySafe(entityId, parentId, ownerId);
                        entity = CreateEntitySafe(entityId, parentId, ownerId);
                    }
                }

                if (throwError && entity == null)
                    throw new EntityNotFoundException("Entity not found: " + entityId);
            }
            return entity;
        }

        internal SecurityEntity[] PeekEntities(params int[] securityEntityIds)
        {
            EnterReadLock();
            try
            {
                return PeekEntitiesSafe(securityEntityIds);
            }
            finally
            {
                ExitReadLock();
            }
        }
        internal SecurityEntity[] PeekEntitiesSafe(params int[] securityEntityIds)
        {
            var result = new SecurityEntity[securityEntityIds.Length];
            var entities = _cache.Entities;
            for (var i = 0; i < securityEntityIds.Length; i++)
                result[i] = entities.TryGetValue(securityEntityIds[i], out var entity) ? entity : null;
            return result;
        }

        internal AccessControlList GetAccessControlList(int entityId, EntryType entryType = EntryType.Normal)
        {
            EnterReadLock();
            try
            {
                var entity = GetEntitySafe(entityId, true);
                var aclInfo = GetFirstAclSafe(entityId, false);
                return aclInfo == null
                    ? AclInfo.CreateEmptyAccessControlList(entityId, entity.IsInherited)
                    : aclInfo.ToAccessControlList(entityId, entryType);
            }
            finally
            {
                ExitReadLock();
            }
        }

        internal AclInfo GetAclInfoCopy(int entityId, EntryType? entryType = null)
        {
            var entity = GetEntitySafe(entityId, false);
            var acl = entity?.Acl;
            return acl == null ? null : entity.Acl.Copy(entryType);
        }

        //---- todo

        internal AclInfo GetFirstAcl(int entityId, bool throwError)
        {
            EnterReadLock();
            try
            {
                return GetFirstAclSafe(entityId, throwError);
            }
            finally
            {
                ExitReadLock();
            }
        }
        internal AclInfo GetFirstAclSafe(int entityId, bool throwError)
        {
            var entity = GetEntitySafe(entityId, throwError);
            return entity?.GetFirstAcl();
        }
        internal int GetFirstAclId(int entityId)
        {
            var acl = GetFirstAcl(entityId, false);
            return acl?.Entity.Id ?? 0;
        }

        /// <summary>
        /// Collects all entity ids in a subtree, including the root entity's.
        /// </summary>
        internal void CollectEntityIds(SecurityEntity rootEntity, List<int> entityIds)
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

        internal void BreakInheritance(IEnumerable<int> entityIds)
        {
            EnterWriteLock();
            try
            {
                foreach (var entityId in entityIds)
                    BreakInheritanceSafe(entityId);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        internal void BreakInheritance(int entityId)
        {
            EnterWriteLock();
            try
            {
                BreakInheritanceSafe(entityId);
            }
            finally
            {
                ExitWriteLock();
            }

        }
        internal void BreakInheritanceSafe(int entityId)
        {
            var entity = GetEntitySafe(entityId, false);
            if (entity == null)
                return;

            entity.IsInherited = false;

            if (entity.Acl == null)
            {
                // creating an empty broken acl
                entity.SetAclSafe(new AclInfo(entityId));
            }
        }

        internal void UndoBreakInheritance(IEnumerable<int> entityIds)
        {
            EnterWriteLock();
            try
            {
                foreach (var entityId in entityIds)
                    UndoBreakInheritanceSafe(entityId);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        internal void UndoBreakInheritance(int entityId)
        {
            EnterWriteLock();
            try
            {
                UndoBreakInheritanceSafe(entityId);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        internal void UndoBreakInheritanceSafe(int entityId)
        {
            var entity = GetEntitySafe(entityId, false);
            if (entity == null)
                return;

            entity.IsInherited = true;

            var acl = entity.Acl;
            if (acl != null && acl.Entries.Count == 0)
                entity.SetAclSafe(null);
        }

        internal SecurityEntity CreateEntity(int entityId, int parentEntityId, int ownerId, bool? isInherited = null, bool? hasExplicitEntry = null)
        {
            EnterWriteLock();
            try
            {
                return CreateEntitySafe(entityId, parentEntityId, ownerId, isInherited, hasExplicitEntry);
            }
            finally
            {
                ExitWriteLock();
            }

        }
        internal SecurityEntity CreateEntitySafe(int entityId, int parentEntityId, int ownerId, bool? isInherited = null, bool? hasExplicitEntry = null)
        {
            SecurityEntity parent = null;
            if (parentEntityId != default)
            {
                // if the parent cannot be loaded (even from the db), this will throw an exception
                parent = GetEntitySafe(parentEntityId, true);
            }

            var entity = new SecurityEntity
            {
                Id = entityId,
                IsInherited = isInherited ?? true,
                OwnerId = ownerId,
                Parent = parent
            };
            parent?.AddChild(entity);
            _cache.Entities[entityId] = entity;

            return entity;
        }

        internal void ModifyEntityOwner(int entityId, int ownerId)
        {
            EnterWriteLock();
            try
            {
                var entity = GetEntitySafe(entityId, true);
                entity.OwnerId = ownerId;
            }
            finally
            {
                ExitWriteLock();
            }
        }

        internal void DeleteEntity(int entityId)
        {
            EnterWriteLock();
            try
            {
                var entity = GetEntitySafe(entityId, false);
                if (entity == null)
                    return;
                DeleteEntityRecursiveSafe(entity);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        private void DeleteEntityRecursiveSafe(SecurityEntity entity)
        {
            var children = entity.Children;
            if (children != null)
                foreach (var child in children.ToArray())
                    DeleteEntityRecursiveSafe(child);

            entity.Parent?.RemoveChild(entity);

            entity.SetAclSafe(null);

            _cache.Entities.Remove(entity.Id);
        }

        internal void MoveEntity(int sourceEntityId, int targetEntityId)
        {
            EnterWriteLock();
            try
            {
                var source = GetEntitySafe(sourceEntityId, false);
                var target = GetEntitySafe(targetEntityId, false);
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

        internal void RemoveAcls(IEnumerable<int> entityIds)
        {
            EnterWriteLock();
            try
            {
                RemoveAclsSafe(entityIds);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        private void RemoveAclsSafe(IEnumerable<int> entityIds)
        {
            foreach (var entityId in entityIds)
            {
                var entity = GetEntitySafe(entityId, false);
                entity?.SetAclSafe(null);
            }
        }

        internal void ApplyAclEditing(AclInfo[] aclsToSet, IEnumerable<int> breaks, IEnumerable<int> undoBreaks,
            List<StoredAce> entriesToRemove, List<int> emptyAclList)
        {
            EnterWriteLock();
            try
            {
                var breakIdArray = breaks as int[] ?? breaks.ToArray();
                var undoBreakIdArray = undoBreaks as int[] ?? undoBreaks.ToArray();
                using (var op = SnTrace.Security.StartOperation("ApplyAcl started."))
                {
                    foreach (var aclInfo in aclsToSet)
                        SetAclSafe(aclInfo);
                    foreach (var entityId in breakIdArray)
                        BreakInheritanceSafe(entityId);
                    foreach (var entityId in undoBreakIdArray)
                        UndoBreakInheritanceSafe(entityId);

                    RemoveEntriesSafe(entriesToRemove);

                    var aclsToRemove = emptyAclList.Where(x => x != default && _cache.Entities[x].IsInherited).ToArray();
                    RemoveAclsSafe(aclsToRemove);

                    op.Successful = true;
                }

                if (SnTrace.Security.Enabled)
                    SnTrace.Security.Write("ApplyAcl finished. SetAcl: {0}, Break: {1}, Unbreak: {2}, Remove: {3}, Empty: {4}",
                        aclsToSet.Length > 0 ? aclsToSet.Length + " (" + aclsToSet[0] + ")" : "0",
                        breakIdArray.Length, undoBreakIdArray.Length, entriesToRemove.Count, emptyAclList.Count);
            }
            finally
            {
                ExitWriteLock();
            }
        }

        private void RemoveEntriesSafe(IEnumerable<StoredAce> entries)
        {
            foreach (var entry in entries)
            {
                // get entity without error
                var entity = GetEntitySafe(entry.EntityId, false);

                // get acl if exists
                var acl = entity?.Acl;

                // get related entry if exists
                var aclEntries = acl?.Entries;
                var entryToRemove = aclEntries?.FirstOrDefault(e => e.EntryType == entry.EntryType && e.IdentityId == entry.IdentityId && e.LocalOnly == entry.LocalOnly);
                if (entryToRemove == null)
                    continue;

                // remove the entry
                aclEntries.Remove(entryToRemove);

                // remove acl if it gets empty and there is no break on the entity
                if (aclEntries.Count == 0 && entity.IsInherited)
                    entity.SetAclSafe(null);
            }
        }

        private void SetAclSafe(AclInfo aclInfo)
        {
            var entity = GetEntitySafe(aclInfo.EntityId, false);
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

        internal void RemoveIdentityRelatedAces(int identityId)
        {
            EnterWriteLock();
            try
            {
                RemoveIdentityRelatedAcesSafe(identityId);
            }
            finally
            {
                ExitWriteLock();
            }
        }
        internal void RemoveIdentityRelatedAcesSafe(int identityId)
        {
            foreach (var entity in _cache.Entities.Values)
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
