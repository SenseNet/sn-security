using System;
using System.Text;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents an aggregated permission settings of one entity for one user or group.
    /// </summary>
    [Serializable]
    public class AccessControlEntry
    {
        /// <summary>
        /// Category of the entry.
        /// </summary>
        public EntryType EntryType { get; set; }
        /// <summary>
        /// Id of the related user or group.
        /// </summary>
        public int IdentityId { get; set; }
        /// <summary>
        /// Set of permissions.
        /// </summary>
        public Permission[] Permissions { get; set; }
        /// <summary>
        /// Gets or sets the inheritance. If the value is true, the entry does not affect the child entities.
        /// </summary>
        public bool LocalOnly { get; set; }

        /// <summary>
        /// Converts the value of this instance to a System.String.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
        public override string ToString()
        {
            var chars = new char[PermissionTypeBase.PermissionCount];
            for (var i = 0; i < chars.Length; i++)
                chars[i] = '_';

            foreach (var perm in Permissions)
            {
                var index = PermissionTypeBase.PermissionCount - PermissionTypeBase.GetPermissionTypeByName(perm.Name).Index - 1;
                if (perm.Deny)
                    chars[index] = '-';
                if (perm.Allow)
                    chars[index] = '+';
            }

            return $"{EntryType}|{(LocalOnly ? '-' : '+')}({IdentityId}):{new string(chars)}";
        }
    }
}
