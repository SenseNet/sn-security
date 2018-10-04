using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SenseNet.Security.Tests
{
    public static class Extensions
    {
        /// <summary>
        /// Shortcut method for test. Example usage: aclEd.Allow("E2", "U1", false, "___________+___");
        /// Bitmask accepts two kind of characters: '_' means active, any other means inactive.
        /// </summary>
        /// <returns></returns>
        public static AclEditor Allow(this AclEditor aclEd, string entity, string identity, string bitMask, bool localOnly = false)
        {
            var perms = GetPermissionTypes(bitMask);
            aclEd.Allow(Tools.GetId(entity), Tools.GetId(identity), localOnly, perms);
            return aclEd;
        }

        private static PermissionTypeBase[] GetPermissionTypes(string bitMask)
        {
            var result = new List<PermissionTypeBase>();
            var length = bitMask.Length;

            for (var i = 0; i < length; i++)
            {
                if(bitMask[i]!='_')
                    result.Add(PermissionTypeBase.GetPermissionTypeByIndex(length - i - 1));
            }

            return result.ToArray();
        }
    }
}
