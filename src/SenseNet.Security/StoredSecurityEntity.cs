namespace SenseNet.Security
{
    /// <summary>
    /// Represents persistable information about a SecurityEntity instance.
    /// </summary>
    public class StoredSecurityEntity
    {
        /// <summary>
        /// Unique id of the entity.
        /// </summary>
        public int Id { get; set; }
        /// <summary>
        /// Id of the owner user or group. 0 means: nobody.
        /// </summary>
        public int OwnerId { get; set; }
        /// <summary>
        /// Id of the parent entity or 0.
        /// </summary>
        public int ParentId { get; set; }
        /// <summary>
        /// Gets or sets the inheritance. True if this entity inherits the permission settings from its parent.
        /// </summary>
        public bool IsInherited { get; set; }
        /// <summary>
        /// True if this entity has any explicit entry.
        /// </summary>
        public bool HasExplicitEntry { get; set; } // used only in the compensation method (reloading in securitycontext)

        /// <summary>
        /// Nullable representation of the ParentId. Null if there is no parent.
        /// </summary>
        public int? nullableParentId
        {
            get { return FromGuid(ParentId); }
            set { ParentId = ToGuid(value); }
        }
        /// <summary>
        /// Nullable representation of the OwnerId. Null if there is no owner.
        /// </summary>
        public int? nullableOwnerId
        {
            get { return FromGuid(OwnerId); }
            set { OwnerId = ToGuid(value); }
        }

        private int? FromGuid(int value)
        {
            return value == default(int) ? null : (int?)value;
        }
        private int ToGuid(int? value)
        {
            return value ?? default(int);
        }
    }
}
