using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;

namespace SenseNet.Security
{
    /// <summary>
    /// Contains read only information about an entity's all explicit and effective permissions 
    /// for building a rich user interface. All changes should be made through the AclEditor class.
    /// </summary>
    [Serializable]
    [DebuggerDisplay("{ToString()}")]
    public class AccessControlList
    {
        /// <summary>Id of the related entity.</summary>
        public int EntityId { get; set; }

        /// <summary>Determines whether the entity inherits any permission values from its ancestors.</summary>
        public bool Inherits { get; set; }

        /// <summary>Set of AccessControlEnties</summary>
        public IEnumerable<AccessControlEntry> Entries { get; set; }

        /// <summary>Converts the value of this instance to a System.String.</summary>
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
        public override string ToString() //UNDONE: ToString
        {
            // "+E1|+U1:____++++,+G1:____++++"

            var sb = new StringBuilder();
            sb.Append(Inherits ? '+' : '-');
            sb.Append("(" + EntityId + ")");
            sb.Append('|');
            var count = 0;
            foreach (var entry in Entries)
            {
                if (count++ > 0)
                    sb.Append(',');
                entry.ToString(sb);
            }
            return sb.ToString();
        }
    }
}
