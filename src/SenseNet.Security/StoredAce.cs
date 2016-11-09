using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents persistent information about an access control entry.
    /// </summary>
    [DebuggerDisplay("Entity: {EntityId}, Identity: {IdentityId}, Local: {LocalOnly}, Allow: {AllowBits}, Deny: {DenyBits}")]
    [Serializable]
    public class StoredAce
    {
        /// <summary>
        /// Id of the entity.
        /// </summary>
        public int EntityId { get; set; }
        /// <summary>
        /// Id of the identity.
        /// </summary>
        public int IdentityId { get; set; }
        /// <summary>
        /// Gets or sets the inheritance. If the value is true, the entry does not affect child entities.
        /// </summary>
        public bool LocalOnly { get; set; }
        /// <summary>
        /// Allowed permissions as bitmask.
        /// </summary>
        public ulong AllowBits { get; set; }
        /// <summary>
        /// Denied permissions as bitmask.
        /// </summary>
        public ulong DenyBits { get; set; }

        /// <summary>
        /// Converts the information of this instance to its equivalent string representation.
        /// </summary>
        [ExcludeFromCodeCoverage]
        public override string ToString()
        {
            var chars = new char[PermissionTypeBase.PermissionCount];
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
            {
                var mask = 1ul << i;
                if ((DenyBits & mask) != 0)
                    chars[PermissionTypeBase.PermissionCount - i - 1] = '-';
                else if ((AllowBits & mask) == mask)
                    chars[PermissionTypeBase.PermissionCount - i - 1] = '+';
                else
                    chars[PermissionTypeBase.PermissionCount - i - 1] = '_';
            }
            return $"({EntityId})|{(LocalOnly ? "-" : "+")}({IdentityId}):{new string(chars)}";
        }

        internal StoredAce Clone()
        {
            return new StoredAce
            {
                EntityId = this.EntityId,
                IdentityId = this.IdentityId,
                LocalOnly = this.LocalOnly,
                AllowBits = this.AllowBits,
                DenyBits = this.DenyBits
            };
        }
    }
}
