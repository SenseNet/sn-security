namespace SenseNet.Security
{
    /// <summary>
    /// Combines the allowed and denied permission sets in one object.
    /// </summary>
    public class PermissionBitMask
    {
        /// <summary>
        /// Represents the allowed permission set. 
        /// </summary>
        public ulong AllowBits;
        /// <summary>
        /// Represents the denied permission set. 
        /// </summary>
        public ulong DenyBits;

        /// <summary>
        /// Combines the two parameters with bitwise | operation and returns with a new value.
        /// </summary>
        public static PermissionBitMask operator |(PermissionBitMask pmask1, PermissionBitMask pmask2)
        {
            return new PermissionBitMask { AllowBits = pmask1.AllowBits | pmask2.AllowBits, DenyBits = pmask1.DenyBits | pmask2.DenyBits };
        }

        // helpers

        private static PermissionBitMask _allAllowed;
        /// <summary>
        /// Bitmask that represents all the supported permission types as allowed.
        /// </summary>
        public static PermissionBitMask AllAllowed
        {
            get
            {
                if (_allAllowed == null)
                {
                    var fullMask = PermissionTypeBase.GetPermissionMask();
                    _allAllowed = new PermissionBitMask { AllowBits = fullMask, DenyBits = 0uL };
                }
                return _allAllowed;
            }
        }
        
        private static PermissionBitMask _allDenied;
        /// <summary>
        /// Bitmask that represents all the supported permission types as denied.
        /// </summary>
        public static PermissionBitMask AllDenied
        {
            get
            {
                if (_allDenied == null)
                {
                    var fullMask = PermissionTypeBase.GetPermissionMask();
                    _allDenied = new PermissionBitMask { AllowBits = 0uL, DenyBits = fullMask };
                }
                return _allDenied;
            }
        }

        private static PermissionBitMask _all;
        /// <summary>
        /// All used PermissionType bits are 1 in allowed and denied bits too.
        /// </summary>
        public static PermissionBitMask All
        {
            get
            {
                if (_all == null)
                {
                    var fullMask = PermissionTypeBase.GetPermissionMask();
                    _all = new PermissionBitMask { AllowBits = fullMask, DenyBits = fullMask };
                }
                return _all;
            }
        }
    }
}
