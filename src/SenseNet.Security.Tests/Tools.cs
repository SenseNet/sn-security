using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using SenseNet.Security.Data;
using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    public static class Tools
    {
        public static int GetId(string name)
        {
            if (name[0] == 'G')
                return TestGroup.GetId(byte.Parse(name.Substring(1)));
            if (name[0] == 'U')
                return TestUser.GetId(byte.Parse(name.Substring(1)));
            if (name[0] == 'E')
                return TestEntity.GetId(byte.Parse(name.Substring(1)));
            throw new NotSupportedException("Invalid name: " + name);
        }

        public static List<Membership> CreateInMemoryMembershipTable(Dictionary<int, SecurityGroup> groups)
        {
            var table = new List<Membership>();
            foreach (var group in groups.Values)
            {
                foreach (var groupMember in group.Groups)
                    table.Add(new Membership { GroupId = group.Id, MemberId = groupMember.Id, IsUser = false });
                foreach (var userMember in group.UserMemberIds)
                    table.Add(new Membership { GroupId = group.Id, MemberId = userMember, IsUser = true });
            }
            return table;
        }
    }
}
