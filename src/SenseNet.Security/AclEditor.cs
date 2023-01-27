using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SenseNet.Security.Messaging.SecurityMessages;
// ReSharper disable ArrangeThisQualifier

namespace SenseNet.Security
{
    /// <summary>
    /// Provides a fluent API for modifying permission settings and inheritance of one or more entities. Operations are executed only at the end, when you call the Apply method.
    /// Execution is atomic and makes the modifications in both the security database and in-memory cache in the whole distributed system.
    /// </summary>
    public class AclEditor
    {
        /// <summary>
        /// Gets the category of entries. Only entries in this category can be edited in this instance.
        /// </summary>
        public EntryType EntryType { get; }

        private enum AggregationType { Allow, Deny }

        /// <summary>
        /// Modified AclInfo set indexed by entity id.
        /// </summary>
        // ReSharper disable once InconsistentNaming
        protected Dictionary<int, AclInfo> _acls = new Dictionary<int, AclInfo>();
        /// <summary>
        /// Id set of the entities where inheritance was cancelled.
        /// </summary>
        // ReSharper disable once InconsistentNaming
        protected List<int> _breaks = new List<int>();
        /// <summary>
        /// Id set of the entities where inheritance was restored.
        /// </summary>
        // ReSharper disable once InconsistentNaming
        protected List<int> _unBreaks = new List<int>();

        /// <summary>
        /// Gets the current SecurityContext
        /// </summary>
        public SecurityContext Context { get; }

        /// <summary>
        /// Initializes a new instance of the AclEditor with a SecurityContext as the current context.
        /// </summary>
        protected internal AclEditor(SecurityContext context, EntryType entryType = EntryType.Normal)
        {
            this.EntryType = entryType;
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
            var ace = EnsureAce(entityId, EntryType, identityId, localOnly);
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
            var ace = EnsureAce(entityId, EntryType, identityId, localOnly);
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
            var ace = EnsureAce(entityId, EntryType, identityId, localOnly);

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
            var ace = EnsureAce(entityId, EntryType, identityId, localOnly);
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
            var ace = EnsureAce(entityId, EntryType, identityId, localOnly);
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
            if(entry.EntryType != this.EntryType)
                throw new InvalidOperationException(
                    $"Inconsistent entry type. EntryType.{entry.EntryType} is not allowed. Expected: {this.EntryType}");

            var ace = EnsureAce(entityId, EntryType, entry.IdentityId, entry.LocalOnly);
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
        /// <param name="convertToExplicit">If true (default), after the break operation all previous effective
        /// permissions will be copied explicitly. WARNING: Only the Normal category will be copied.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        [Obsolete("Use the BreakInheritance(int entityId, EntryType[] categoriesToCopy) method instead")]
        public AclEditor BreakInheritance(int entityId, bool convertToExplicit = true)
        {
            _unBreaks.Remove(entityId);
            if (!_breaks.Contains(entityId))
                _breaks.Add(entityId);

            if (convertToExplicit)
                CopyEffectivePermissions(entityId, new[] {EntryType.Normal});

            return this;
        }
        /// <summary>
        /// Cancels the permission inheritance on the requested entity.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="categoriesToCopy">After the break operation, all previous effective permissions will be
        /// copied explicitly that are matched any of the given entry types.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        public AclEditor BreakInheritance(int entityId, EntryType[] categoriesToCopy)
        {
            _unBreaks.Remove(entityId);
            if (!_breaks.Contains(entityId))
                _breaks.Add(entityId);
            CopyEffectivePermissions(entityId, categoriesToCopy);
            return this;
        }
        /// <summary>
        /// Restores the permission inheritance on the requested entity.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="normalize">If true (default is false), the unnecessary explicit entries will be removed.
        /// WARNING: Only the Normal category will be copied.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        [Obsolete("Use the UnBreakInheritance(int entityId, EntryType[] categoriesToNormalize) method instead", true)]
        public AclEditor UnbreakInheritance(int entityId, bool normalize = false)
        {
            _breaks.Remove(entityId);
            if (!_unBreaks.Contains(entityId))
                _unBreaks.Add(entityId);

            if (normalize)
                NormalizeExplicitPermissions(entityId, new[] { EntryType.Normal });

            return this;
        }
        [Obsolete("Use the overload with correct name.", true)]
        public AclEditor UnbreakInheritance(int entityId, EntryType[] categoriesToNormalize)
        {
            return UnBreakInheritance(entityId, categoriesToNormalize);
        }
        /// <summary>
        /// Restores the permission inheritance on the requested entity.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="categoriesToNormalize">Unnecessary explicit entries
        /// that match these categories will be removed.</param>
        /// <returns>A reference to this instance for calling more operations.</returns>
        public AclEditor UnBreakInheritance(int entityId, EntryType[] categoriesToNormalize)
        {
            _breaks.Remove(entityId);
            if (!_unBreaks.Contains(entityId))
                _unBreaks.Add(entityId);
            if (categoriesToNormalize != null && categoriesToNormalize.Length > 0)
                NormalizeExplicitPermissions(entityId, categoriesToNormalize);
            return this;
        }

        /// <summary>
        /// Executes all modifications. If you do not call this method, no changes will be made.
        /// </summary>
        [Obsolete("Use async version instead.", true)]
        public virtual void Apply()
        {
            var activity = new SetAclActivity(_acls.Values.ToArray(), _breaks, _unBreaks);
            activity.Execute(this.Context);
        }
        /// <summary>
        /// Executes all modifications. If you do not call this method, no changes will be made.
        /// </summary>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        public virtual async Task ApplyAsync(CancellationToken cancel)
        {
            var activity = new SetAclActivity(_acls.Values.ToArray(), _breaks, _unBreaks);
            await activity.ExecuteAsync(this.Context, cancel).ConfigureAwait(false);
        }

        /// <summary>
        /// Copies effective permissions to explicit access control entries.
        /// </summary>
        /// <param name="entityId">The requested entity.</param>
        /// <param name="entryTypes">Array of <see cref="EntryType"/>. Only items of these types will be copied
        /// Copy is skipped if the array is empty.</param>
        internal AclEditor CopyEffectivePermissions(int entityId, EntryType[] entryTypes)
        {
            foreach (var entryType in entryTypes)
            {
                foreach (var refAce in this.Context.Evaluator.GetEffectiveEntries(entityId, null, entryType))
                {
                    var ace = EnsureAce(entityId, refAce.EntryType, refAce.IdentityId, refAce.LocalOnly);
                    ace.AllowBits |= refAce.AllowBits;
                    ace.DenyBits |= refAce.DenyBits;
                }
            }
            return this;
        }
        /// <summary>
        /// Removes inherited effective permissions from the explicit setting collection.
        /// </summary>
        internal AclEditor NormalizeExplicitPermissions(int entityId, EntryType[] entryTypes)
        {
            var firstAcl = Context.SecuritySystem.EntityManager.GetFirstAcl(entityId, false);
            if (firstAcl == null)
                return this; // there is no settings.
            if (entityId != firstAcl.EntityId)
                return this; // there is no explicit settings.

            var evaluator = this.Context.Evaluator;

            var parentAcl = firstAcl.Parent;
            if (parentAcl == null)
                return this; // this is the root setting

            var localAces = firstAcl.Entries;
            // Ensure all existing explicit entries on the output
            // to avoid incorrect empty ACL detection in the SetAclActivity
            foreach (var ace in localAces)
            {
                var editorAce = EnsureAce(entityId, ace.EntryType, ace.IdentityId, ace.LocalOnly);
                editorAce.AllowBits = ace.AllowBits;
                editorAce.DenyBits = ace.DenyBits;
            }

            foreach (var entryType in entryTypes)
            {
                foreach (var refAce in evaluator.GetEffectiveEntries(parentAcl.EntityId, null, entryType))
                {
                    var hasLocalAce = localAces.Any(x =>
                        x.EntryType == refAce.EntryType && x.IdentityId == refAce.IdentityId && x.LocalOnly == refAce.LocalOnly);
                    if (hasLocalAce)
                    {
                        var editorAce = EnsureAce(entityId, entryType, refAce.IdentityId, refAce.LocalOnly);
                        editorAce.AllowBits &= ~refAce.AllowBits; // clears all allow bits of refAce
                        editorAce.DenyBits &= ~refAce.DenyBits; // clears all deny bits of refAce
                    }
                }
            }

            return this;
        }

        private AceInfo EnsureAce(int entityId, EntryType entryType, int identityId, bool localOnly)
        {
            var aclInfo = EnsureAcl(entityId);
            var aceInfo = aclInfo.Entries.FirstOrDefault(
                x => x.EntryType == entryType && x.IdentityId == identityId && x.LocalOnly == localOnly);
            if (aceInfo == null)
            {
                aclInfo.Entries.Add(aceInfo = new AceInfo
                {
                    EntryType = entryType,
                    IdentityId = identityId,
                    LocalOnly = localOnly
                });
            }
            return aceInfo;
        }
        private AclInfo EnsureAcl(int entityId)
        {
            if (!_acls.TryGetValue(entityId, out var aclInfo))
            {
                aclInfo = Context.SecuritySystem.EntityManager.GetAclInfoCopy(entityId, this.EntryType);
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

        private static IEnumerable<PermissionTypeBase> AggregateAffectedPermissions(PermissionTypeBase[] permissions, AggregationType aggregationType)
        {
            var aggregation = new Dictionary<int, PermissionTypeBase>();
            if (permissions != null)
                foreach (var permission in permissions)
                    AggregateAffectedPermissions(permission, aggregationType, aggregation);
            return aggregation.Values.ToArray();
        }
        private static void AggregateAffectedPermissions(PermissionTypeBase permission, AggregationType aggregationType, Dictionary<int, PermissionTypeBase> aggregation)
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
