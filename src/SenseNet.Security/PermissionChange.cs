namespace SenseNet.Security
{
    /// <summary>
    /// Represents a changed permission set of the identity on the entity.
    /// </summary>
    public class PermissionChange
    {
        /// <summary>
        /// Related entity object.
        /// </summary>
        public SecurityEntity Entity { get; set; }
        /// <summary>
        /// Id of the related identity.
        /// </summary>
        public int IdentityId { get; set; }
        /// <summary>
        /// Every bit indicate a permission modification state: 1 changed, 0 unchanged.
        /// </summary>
        public PermissionBitMask ChangedBits { get; set; }
    }
}
