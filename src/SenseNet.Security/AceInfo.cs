using Newtonsoft.Json;
using System;
using System.Diagnostics;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents in-memory information about an access control entry.
    /// </summary>
    [DebuggerDisplay("{" + nameof(ToString) + "()}")]
    [Serializable]
    public class AceInfo
    {
        /// <summary>
        /// Category of the entry.
        /// </summary>
        [JsonProperty]
        public EntryType EntryType { get; set; }
        /// <summary>
        /// Id of the identity.
        /// </summary>
        [JsonProperty]
        public int IdentityId { get; internal set; }
        /// <summary>
        /// Gets the inheritance state.
        /// </summary>
        [JsonProperty]
        public bool LocalOnly { get; internal set; }
        /// <summary>
        /// Allowed permissions as bitmask.
        /// </summary>
        [JsonProperty]
        public ulong AllowBits { get; internal set; }
        /// <summary>
        /// Denied permissions as bitmask.
        /// </summary>
        [JsonProperty]
        public ulong DenyBits { get; internal set; }

        internal AceInfo Copy()
        {
            return new AceInfo
            {
                IdentityId = IdentityId,
                EntryType = EntryType,
                LocalOnly = LocalOnly,
                AllowBits = AllowBits,
                DenyBits = DenyBits
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
