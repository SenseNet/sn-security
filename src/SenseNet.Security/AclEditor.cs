﻿using System;
using System.Collections.Generic;
using System.Linq;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security
{
    /// <summary>
    /// Provides a fluent API for modifying permission settings and inheritance of one or more entities. Operations are executed only at the end, when you call the Apply method.
    /// Execution is atomic and makes the modifications in both the security database and in-memory cache in the whole distributed system.
    /// </summary>
    public class AclEditor
    {
        private enum AggregationType { Allow, Deny }

        /// <summary>
        /// Modified AclInfo set indexed by entity id.
        /// </summary>
        protected Dictionary<int, AclInfo> _acls = new Dictionary<int, AclInfo>();
        /// <summary>
        /// Id set of the entities where inheritance was cancelled.
        /// </summary>
        protected List<int> _breaks = new List<int>();
        /// <summary>
        /// Id set of the entities where inheritance was restored.
        /// </summary>
        protected List<int> _unbreaks = new List<int>();

        /// <summary>
        /// Gets the current SecurityContext
        /// </summary>
        public SecurityContext Context { get; }

        /// <summary>
        /// Shortcut of the constructor.
        /// Returns with a new instance of the AclEditor with a SecurityContext as the current context.
        /// </summary>
        public static AclEditor Create(SecurityContext context) { return new AclEditor(context); }

        /// <summary>
        /// Initializes a new instance of the AclEditor with a SecurityContext as the current context.
        /// </summary>
        /// <param name="context"></param>
        protected internal AclEditor(SecurityContext context)
        {
            this.Context = context;
        }

        /// <summary>
        /// Allows one or more permissions on the requested entity for the requested identity.
        /// Empty or null permission set is ineffective so this method cannot be used
        /// to reset the explicitly allowed permissions.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="identityId">The requested identity.</param>
        /// <param name="localOnly">False if the edited entry is inheritable.</param>
        /// <param name="permissions">One or more permissions.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        public AclEditor Allow(int entityId, int identityId, bool localOnly, params PermissionTypeBase[] permissions)
        {
            var ace = EnsureAce(entityId, identityId, localOnly);
            var perms = AggregateAffectedPermissions(permissions, AggregationType.Allow);
            foreach (var perm in perms)
            {
                ace.DenyBits &= ~perm.Mask;
                ace.AllowBits |= perm.Mask;
            }
            return this;
        }
        /// <summary>
        /// Denies one or more permissions on the requested entity for the requested identity.
        /// Empty or null permission set is ineffective so this method cannot be used
        /// to reset the explicitly denied permissions.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="identityId">The requested identity.</param>
        /// <param name="localOnly">False if the edited entry is inheritable.</param>
        /// <param name="permissions">One or more permissions.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        public AclEditor Deny(int entityId, int identityId, bool localOnly, params PermissionTypeBase[] permissions)
        {
            var ace = EnsureAce(entityId, identityId, localOnly);
            var perms = AggregateAffectedPermissions(permissions, AggregationType.Deny);
            foreach (var perm in perms)
            {
                ace.AllowBits &= ~perm.Mask;
                ace.DenyBits |= perm.Mask;
            }
            return this;
        }
        /// <summary>
        /// Clears one or more permissions on the requested entity for the requested identity.
        /// Cleared permission is "Undefined" which means not "Allowed" and not "Denied".
        /// Empty or null permission set is ineffective.
        /// Entry will be deleted if it will be empty after clearing.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="identityId">The requested identity.</param>
        /// <param name="localOnly">False if the edited entry is inheritable.</param>
        /// <param name="permissions">One or more permissions.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        public AclEditor ClearPermission(int entityId, int identityId, bool localOnly, params PermissionTypeBase[] permissions)
        {
            var ace = EnsureAce(entityId, identityId, localOnly);

            var perms = AggregateAffectedPermissions(permissions, AggregationType.Allow);
            foreach (var perm in perms)
                ace.DenyBits &= ~perm.Mask;

            perms = AggregateAffectedPermissions(permissions, AggregationType.Deny);
            foreach (var perm in perms)
                ace.AllowBits &= ~perm.Mask;

            return this;
        }
        /// <summary>
        /// Sets the allowed and denied permissions by the passed bitmask.
        /// This method can not reset any allowed or denied permissions.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="identityId">The requested identity.</param>
        /// <param name="localOnly">False if the edited entry is inheritable.</param>
        /// <param name="permissionMask">Contains one or more permissions to allow or deny.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        public AclEditor Set(int entityId, int identityId, bool localOnly, PermissionBitMask permissionMask)
        {
            var ace = EnsureAce(entityId, identityId, localOnly);
            ace.AllowBits |= permissionMask.AllowBits;
            ace.DenyBits |= permissionMask.DenyBits;
            return this;
        }
        /// <summary>
        /// Resets the allowed and denied permissions by the passed bitmask.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="identityId">The requested identity.</param>
        /// <param name="localOnly">False if the edited entry is inheritable.</param>
        /// <param name="permissionMask">Contains one or more permissions to allow or deny.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        public AclEditor Reset(int entityId, int identityId, bool localOnly, PermissionBitMask permissionMask)
        {
            var ace = EnsureAce(entityId, identityId, localOnly);
            ace.AllowBits &= ~permissionMask.AllowBits;
            ace.DenyBits &= ~permissionMask.DenyBits;
            return this;
        }

        /// <summary>
        /// Copies the permission settings from the passed entry to the requested entity's explicit entry.
        /// </summary>
        /// <param name="entityId">Id of the requested entity.</param>
        /// <param name="entry">The source entry.</param>
        /// <param name="reset">If true, the original allowed and denied permissions will be cleared before copy.
        /// Otherwise the result set will contain the original and source entry permission settings.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        public AclEditor SetEntry(int entityId, AceInfo entry, bool reset)
        {
            var ace = EnsureAce(entityId, entry.IdentityId, entry.LocalOnly);
            if (reset)
            {
                ace.AllowBits = entry.AllowBits;
                ace.DenyBits = entry.DenyBits;
            }
            else
            {
                ace.AllowBits |= entry.AllowBits;
                ace.DenyBits |= entry.DenyBits;
            }
            return this;
        }

        /// <summary>
        /// Cancels the permission inheritance on the requested entity.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="convertToExplicit">If true (default), after the break operation all previous effective permissions will be copied explicitly.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        public AclEditor BreakInheritance(int entityId, bool convertToExplicit = true)
        {
            _unbreaks.Remove(entityId);
            if (!_breaks.Contains(entityId))
                _breaks.Add(entityId);

            if (convertToExplicit)
                CopyEffectivePermissions(entityId);

            return this;
        }
        /// <summary>
        /// Restores the permission inheritance on the requested entity.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="normalize">If true (default is false), the unnecessary explicit entries will be removed.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        public AclEditor UnbreakInheritance(int entityId, bool normalize = false)
        {
            _breaks.Remove(entityId);
            if (!_unbreaks.Contains(entityId))
                _unbreaks.Add(entityId);

            if (normalize)
                NormalizeExplicitePermissions(entityId);

            return this;
        }

        /// <summary>
        /// Executes all modifications. If you do not call this method, no changes will be made.
        /// </summary>
        public virtual void Apply()
        {
            var activity = new SetAclActivity(_acls.Values, _breaks, _unbreaks);
            activity.Execute(this.Context);
        }

        /// <summary>
        /// Copies effective permissions to explicite access control entries.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        internal AclEditor CopyEffectivePermissions(int entityId)
        {
            foreach (var refAce in this.Context.Evaluator.GetEffectiveEntries(entityId))
            {
                var ace = EnsureAce(entityId, refAce.IdentityId, refAce.LocalOnly);
                ace.AllowBits |= refAce.AllowBits;
                ace.DenyBits |= refAce.DenyBits;
            }
            return this;
        }
        /// <summary>
        /// Removes inherited effective permissions from the explicite setting collection.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        internal AclEditor NormalizeExplicitePermissions(int entityId)
        {
            var firstAcl = SecurityEntity.GetFirstAcl(this.Context, entityId, false);
            if (firstAcl == null)
                return this; // there is no settings.
            if (entityId != firstAcl.EntityId)
                return this; // there is no explicite settings.

            var evaluator = this.Context.Evaluator;

            var parentAcl = firstAcl.Parent;
            if (parentAcl == null)
                return this; // this is the root setting

            var localAces = firstAcl.Entries;
            foreach (var refAce in evaluator.GetEffectiveEntries(parentAcl.EntityId))
            {
                var hasLocalAce = localAces.Any(x => x.IdentityId == refAce.IdentityId && x.LocalOnly == refAce.LocalOnly);
                if (hasLocalAce)
                {
                    var editorAce = EnsureAce(entityId, refAce.IdentityId, refAce.LocalOnly);
                    editorAce.AllowBits &= ~refAce.AllowBits; // clears all allow bits of refAce
                    editorAce.DenyBits &= ~refAce.DenyBits;   // clears all deny bits of refAce
                }
            }

            return this;
        }

        private AceInfo EnsureAce(int entityId, int identityId, bool localOnly)
        {
            var aclInfo = EnsureAcl(entityId);
            var aceInfo = aclInfo.Entries.FirstOrDefault(x => x.IdentityId == identityId && x.LocalOnly == localOnly);
            if (aceInfo == null)
            {
                //UNDONE: EntryType initialization?
                aclInfo.Entries.Add(aceInfo = new AceInfo { IdentityId = identityId, LocalOnly = localOnly });
            }
            return aceInfo;
        }
        private AclInfo EnsureAcl(int entityId)
        {
            AclInfo aclInfo;
            if (!_acls.TryGetValue(entityId, out aclInfo))
            {
                aclInfo = SecurityEntity.GetAclInfoCopy(this.Context, entityId);
                if (aclInfo == null)
                {
                    // creating an empty acl
                    this.Context.GetSecurityEntity(entityId);
                    aclInfo = new AclInfo(entityId);
                }
                _acls.Add(entityId, aclInfo);
            }
            return aclInfo;
        }

        private IEnumerable<PermissionTypeBase> AggregateAffectedPermissions(PermissionTypeBase[] permissions, AggregationType aggregationType)
        {
            var aggregation = new Dictionary<int, PermissionTypeBase>();
            if (permissions != null)
                foreach (var permission in permissions)
                    AggregateAffectedPermissions(permission, aggregationType, aggregation);
            return aggregation.Values.ToArray();
        }
        private void AggregateAffectedPermissions(PermissionTypeBase permission, AggregationType aggregationType, Dictionary<int, PermissionTypeBase> aggregation)
        {
            if (aggregation.ContainsKey(permission.Index))
                return;

            aggregation[permission.Index] = permission;
            PermissionTypeBase[] morePermissions;
            switch (aggregationType)
            {
                case AggregationType.Allow:
                    morePermissions = permission.Allows;
                    break;
                case AggregationType.Deny:
                    morePermissions = permission.Denies.ToArray();
                    break;
                default:
                    throw new NotSupportedException("Unknown AggregationType: " + aggregationType);
            }

            if (morePermissions?.Length > 0)
                foreach (var perm in morePermissions)
                    if (perm != null)
                        AggregateAffectedPermissions(perm, aggregationType, aggregation);
        }
    }
}
