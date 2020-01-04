using System;
using System.Linq;
using System.Text;
using System.Runtime.Serialization;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents an error that occurs when a user does not have enough permissions to execute an operation.
    /// </summary>
    [Serializable]
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    public class AccessDeniedException : Exception
    {
        /// <summary>Initializes a new instance of the AccessDeniedException class.</summary>
        public AccessDeniedException(string message, string path, int entityId, ISecurityUser user, PermissionTypeBase[] permissionTypes)
            : base(GetMessage(message, path, entityId, user, permissionTypes)) { }
        /// <summary>Initializes a new instance of the AccessDeniedException class with serialized data.</summary>
        protected AccessDeniedException(SerializationInfo info, StreamingContext context)
            : base(info, context) {}

        private static string GetMessage(string msg, string path, int entityId, ISecurityUser user, PermissionTypeBase[] permissionTypes)
        {
            var sb = new StringBuilder(msg ?? "Access denied.");
            if (path != null)
                sb.Append(" Path: ").Append(path);
            if (entityId != default)
                sb.Append(" EntityId: ").Append(entityId);
            if (user != null)
                sb.Append(" UserId: ").Append(user.Id);
            if (permissionTypes != null)
                sb.Append(" PermissionTypes: ").Append(string.Join(", ", permissionTypes.Select(pt=>pt.Name)));
            return sb.ToString();
        }
    }
}