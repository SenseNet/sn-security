using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace SenseNet.Security
{
    /// <summary>
    /// Permission representation in AccessControlEntry.
    /// </summary>
    [DebuggerDisplay("{" + nameof(ToString) + "()}")]
    [Serializable]
    public class Permission
    {
        /// <summary>
        /// Name of the permission.
        /// </summary>
        public string Name { get; set; }
        /// <summary>
        /// True if the permission is allowed.
        /// </summary>
        public bool Allow { get; set; }
        /// <summary>
        /// True if the permission is denied.
        /// </summary>
        public bool Deny { get; set; }

        /// <summary>
        /// Id of the entity on the ancestor chain where this permission is allowed explicitly.
        /// </summary>
        public int AllowFrom { get; set; }
        /// <summary>
        /// Id of the entity on the ancestor chain where this permission is denied explicitly.
        /// </summary>
        public int DenyFrom { get; set; }

        /// <summary>
        /// Editing is enabled if this permission has an explicit setting.
        /// </summary>
        public bool AllowEnabled => AllowFrom == 0;

        /// <summary>
        /// Editing is enabled if this permission has an explicit setting.
        /// </summary>
        public bool DenyEnabled => DenyFrom == 0;

        /// <summary>Converts the value of this instance to a System.String.</summary>
        [ExcludeFromCodeCoverage]
        [SuppressMessage("ReSharper", "ConvertIfStatementToReturnStatement")]
        public override string ToString()
        {
            if (Deny)
                return $"{Name}: denied, {(DenyFrom == 0 ? "" : "not ")}editable";
            if (Allow)
                return $"{Name}: allowed, {(AllowFrom == 0 ? "" : "not ")}editable";
            return $"{Name}: undefined, editable";
        }
    }
}
