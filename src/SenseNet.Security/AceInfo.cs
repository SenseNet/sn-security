using System;
using System.Collections.Generic;
using System.Diagnostics;
using SenseNet.Security.Configuration;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents in-memory information about an access control entry.
    /// </summary>
    [DebuggerDisplay("{ToString()}")]
    [Serializable]
    public class AceInfo
    {
        /// <summary>
        /// Cateory of the entry.
        /// </summary>
        public EntryType EntryType { get; set; }
        /// <summary>
        /// Id of the identity.
        /// </summary>
        public int IdentityId { get; internal set; }
        /// <summary>
        /// Gets the inheritance state.
        /// </summary>
        public bool LocalOnly { get; internal set; }
        /// <summary>
        /// Allowed permissions as bitmask.
        /// </summary>
        public ulong AllowBits { get; internal set; }
        /// <summary>
        /// Denied permissions as bitmask.
        /// </summary>
        public ulong DenyBits { get; internal set; }

        internal static List<AceInfo> GetElevatedAces(EntryType? entryType)
        {
            return new List<AceInfo>
            {
                new AceInfo
                {
                    IdentityId = Identities.SystemUserId,
                    EntryType = entryType ?? EntryType.Normal,
                    LocalOnly = false,
                    AllowBits = ulong.MaxValue,
                    DenyBits = 0ul
                }
            };
        }

        internal AceInfo Copy()
        {
            return new AceInfo
            {
                IdentityId = this.IdentityId,
                EntryType = this.EntryType,
                LocalOnly = this.LocalOnly,
                AllowBits = this.AllowBits,
                DenyBits = this.DenyBits
            };
        }

        /// <summary>
        /// Converts the information of this instance to its equivalent string representation.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
        public override string ToString()
        {
            return $"{EntryType}|{(LocalOnly ? "-" : "+")}({IdentityId}):{BitsToString()}";
        }
        /// <summary>
        /// Converts the AllowBits and DenyBits of this instance to its equivalent string representation.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
        public string BitsToString()
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
            return new string(chars);
        }
        /// <summary>
        /// Converts the AllowBits and DenyBits of this instance to its equivalent PermissionValue array.
        /// </summary>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
        public PermissionValue[] GetPermissionValues()
        {
            var values = new PermissionValue[PermissionTypeBase.PermissionCount];
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
            {
                var mask = 1ul << i;
                if ((DenyBits & mask) != 0)
                    values[i] = PermissionValue.Denied; // '-';
                else if ((AllowBits & mask) == mask)
                    values[i] = PermissionValue.Allowed; // '+';
                else
                    values[i] = PermissionValue.Undefined; // '_';
            }
            return values;
        }
    }
}
