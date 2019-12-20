using System;
using System.Collections.Generic;
using System.Linq;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents one permission in the system. 3rd party developers may inherit from this base class and 
    /// provide others with named permissions.
    /// </summary>
    public abstract class PermissionTypeBase
    {
        /// <summary>Permission type capacity.</summary>
        public static readonly int PermissionMaxCount = sizeof(long) * 8;
        /// <summary>Count of registered permission types.</summary>
        public static int PermissionCount => _permissionDict.Count;

        private static readonly PermissionTypeBase[] _permissionArray;
        private static readonly Dictionary<string, PermissionTypeBase> _permissionDict;

        static PermissionTypeBase()
        {
            _permissionArray = new PermissionTypeBase[PermissionMaxCount];
            _permissionDict = new Dictionary<string, PermissionTypeBase>();
        }

        /*==============================================================================*/

        /// <summary> 0 based index. Max value is the bit count of long.</summary>
        public int Index { get; }
        /// <summary>Case sensitive unique name.</summary>
        public string Name { get; }
        /// <summary>
        /// Bitmask value of the permission type. The bit on the position determined by Index is 1, any other is 0.
        /// Calculated in construction time.
        /// </summary>
        public ulong Mask { get; }

        /// <summary>
        /// Provides other permission types that must be allowed if this permission is allowed.
        /// Can contain zero, one or more existing permission types. These forced settings
        /// have chained effect so it is strongly recommended that this array contain
        /// such permission types that have a smaller index than the owner.
        /// </summary>
        public PermissionTypeBase[] Allows { get; set; }
        internal List<PermissionTypeBase> Denies { get; }

        /// <summary>
        /// Creates and memorizes the instance of the permission type with passed index and name.
        /// Index is 0 &lt;= i &lt; bit count of ulong (64).
        /// </summary>
        /// <param name="name">Case sensitive unique name.</param>
        /// <param name="index">Set of values: 0 &lt;= i &lt; 64 (bit count of ulong).</param>
        protected PermissionTypeBase(string name, int index)
        {
            Index = index;
            Name = name;
            Mask = 1ul << index;
            _permissionArray[index] = this;
            _permissionDict[Name] = this;
            Denies = new List<PermissionTypeBase>();
        }

        internal static PermissionTypeBase[] GetPermissionTypes()
        {
            return _permissionDict.Values.ToArray();
        }

        internal static void InferForcedRelations()
        {
            foreach (var permType in _permissionDict.Values)
                if (permType.Allows != null)
                    foreach (var allowed in permType.Allows)
                        allowed?.Denies.Add(permType);
        }

        /// <summary>
        /// Returns a PermissionTypeBase instance by the passed 0 based index.
        /// </summary>
        /// <param name="index">0 based index value.</param>
        /// <returns>The matched permission type or null if it does not exist.</returns>
        /// <exception cref="IndexOutOfRangeException">IndexOutOfRangeException</exception>
        public static PermissionTypeBase GetPermissionTypeByIndex(int index)
        {
            if (index < 0 || index >= _permissionArray.Length)
                return null;
            return _permissionArray[index];
        }
        /// <summary>
        /// Returns a PermissionTypeBase instance by the passed name.
        /// </summary>
        /// <param name="name">Case sensitive name of the permission.</param>
        /// <returns>The matched permission type or null if it does not exist.</returns>
        /// <exception cref="KeyNotFoundException">KeyNotFoundException</exception>
        public static PermissionTypeBase GetPermissionTypeByName(string name)
        {
            return _permissionDict.TryGetValue(name, out var result) ? result : null;
        }

        /// <summary>
        /// Returns with the aggregated bitmask of the passed permission type set.
        /// </summary>
        /// <param name="permissionTypes">Empty parameter means all the permission types.
        /// Permission type order is irrelevant.</param>
        /// <returns>Aggregated bitmask.</returns>
        public static ulong GetPermissionMask(IEnumerable<PermissionTypeBase> permissionTypes = null)
        {
            var permTypes = permissionTypes ?? _permissionArray;
            var mask = 0ul;
            // ReSharper disable once LoopCanBeConvertedToQuery
            foreach (var permissionType in permTypes)
                mask |= permissionType.Mask;
            return mask;
        }

        /// <summary>
        /// Converts a permission to a bitmask.
        /// </summary>
        public static implicit operator PermissionBitMask(PermissionTypeBase pt)
        {
            return new PermissionBitMask { AllowBits = pt.Mask };
        }
        /// <summary>
        /// Negates all bits.
        /// </summary>
        public static PermissionBitMask operator ~(PermissionTypeBase pt)
        {
            return new PermissionBitMask { DenyBits = pt.Mask };
        }
        /// <summary>
        /// Returns a value that has combined bit-masks of the parameters.
        /// </summary>
        public static PermissionBitMask operator |(PermissionTypeBase pt1, PermissionTypeBase pt2)
        {
            var pmask1 = new PermissionBitMask { AllowBits = pt1.Mask };
            var pmask2 = new PermissionBitMask { AllowBits = pt2.Mask };
            return new PermissionBitMask { AllowBits = pmask1.AllowBits | pmask2.AllowBits, DenyBits = pmask1.DenyBits | pmask2.DenyBits };
        }
    }
}
