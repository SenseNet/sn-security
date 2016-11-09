namespace SenseNet.Security
{
    /// <summary>
    /// Level of permission in the PermissionQuery operations.
    /// </summary>
    public enum PermissionLevel
    {
        /// <summary>Query only allowed permissions.</summary>
        Allowed,
        /// <summary>Query only denied permissions.</summary>
        Denied,
        /// <summary>Query allowed and denied permissions too.</summary>
        AllowedOrDenied
    }
}
