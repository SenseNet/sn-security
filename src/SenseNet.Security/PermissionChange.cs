namespace SenseNet.Security
{
    /// <summary>
    /// Represents a changed permission set of the identity on the entity.
    /// </summary>
    public class PermissionChange
    {
        /// <summary>
        /// Gets the related entity object.
        /// </summary>
        public SecurityEntity Entity { get; }
        /// <summary>
        /// Gets the Id of the related identity.
        /// </summary>
        public int IdentityId { get; }
        /// <summary>
        /// Gets the type of changed entry.
        /// </summary>
        public EntryType EntryType { get; }
        /// <summary>
        /// Gets the changed bitmask. Every bit indicate a permission modification state: 1 changed, 0 unchanged.
        /// </summary>
        public PermissionBitMask ChangedBits { get; }

        internal PermissionChange(SecurityEntity entity, AceInfo entry) : this(entity, entry.IdentityId,
            entry.EntryType,
            entry.AllowBits, entry.DenyBits)
        {
        }

        internal PermissionChange(SecurityEntity entity, int identityId, EntryType entryType,
            ulong changedAllowBits, ulong changedDenyBits) : this(entity, identityId, entryType,
                new PermissionBitMask {AllowBits = changedAllowBits, DenyBits = changedDenyBits })
        {
        }

        internal PermissionChange(SecurityEntity entity, int identityId, EntryType entryType,
            PermissionBitMask changedBits)
        {
            Entity = entity;
            IdentityId = identityId;
            EntryType = entryType;
            ChangedBits = changedBits;
        }
    }
}
