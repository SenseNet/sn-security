using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents a group node int the in-memory membership graph.
    /// </summary>
    [DebuggerDisplay("{" + nameof(ToString) + "()}")]
    public class SecurityGroup
    {
        /// <summary>
        /// Id of the group.
        /// </summary>
        public int Id { get; set; }
        /// <summary>
        /// Groups that contain this group directly.
        /// </summary>
        public List<SecurityGroup> ParentGroups { get; set; }
        /// <summary>
        /// Member groups.
        /// </summary>
        public List<SecurityGroup> Groups { get; set; }
        /// <summary>
        /// Member user ids.
        /// </summary>
        public List<int> UserMemberIds { get; set; }

        /// <summary>
        /// Initializes a new instance of the SecurityGroup
        /// </summary>
        public SecurityGroup(int id)
        {
            Id = id;
            Groups = new List<SecurityGroup>();
            ParentGroups = new List<SecurityGroup>();
            UserMemberIds = new List<int>();
        }

        /// <summary>
        /// Converts the information of this instance to its equivalent string representation.
        /// </summary>
        public override string ToString()
        {
            var userStr = string.Join(",", this.UserMemberIds.Select(x => "U" + x));
            var groupStr = string.Join(",", this.Groups.Select(x => "G" + x.Id));
            var parentsStr = string.Join(",", this.ParentGroups.Select(x => "G" + x.Id));
            return "G" + Id + ":" + userStr + ", " + groupStr + "(" + parentsStr + ")";
        }
    }
}
