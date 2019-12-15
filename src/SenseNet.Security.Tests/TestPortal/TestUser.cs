using System.Collections.Generic;

namespace SenseNet.Security.Tests.TestPortal
{
    public class TestUser : ISecurityUser
    {
        public int Id { get; set; }

        public string Name { get; set; }

        //=================================================================================

        public static readonly TestUser User1 = new TestUser { Id = 201, Name = "U1" };
        public static readonly TestUser User2 = new TestUser { Id = 202, Name = "U2" };
        public static readonly TestUser User3 = new TestUser { Id = 203, Name = "U3" };
        public static readonly TestUser User4 = new TestUser { Id = 204, Name = "U4" };
        public static readonly TestUser User5 = new TestUser { Id = 205, Name = "U5" };
        public static readonly TestUser User6 = new TestUser { Id = 206, Name = "U6" };

        public static int GetId(byte index)
        {
            return 200 + index;
        }

        public IEnumerable<int> GetDynamicGroups(int entityId)
        {
            return _dynamicGroups;                                      // for tests only
        }

        IEnumerable<int> _dynamicGroups;                               // for tests only
        internal void SetDynamicGroups(IEnumerable<int> dynamicGroups)  // for tests only
        {
            _dynamicGroups = dynamicGroups;
        }
    }
}
