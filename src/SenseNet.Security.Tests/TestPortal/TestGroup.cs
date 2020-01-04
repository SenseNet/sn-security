using System.Collections.Generic;
using System.Linq;

namespace SenseNet.Security.Tests.TestPortal
{
    public class TestGroup
    {
        public int Id { get; set; }

        public string Name { get; set; }

        public static TestGroup CreateTestGroup(byte index)
        {
            return new TestGroup {Id = GetId(index), Name = "G" + index};
        }

        private List<TestGroup> _groups = new List<TestGroup>();
        public IEnumerable<TestGroup> GetGroupMembers()
        {
            return _groups;
        }
        public void SetGroupMembers(IEnumerable<TestGroup> groups)
        {
            _groups = groups.ToList();
        }

        private List<TestGroup> _containerGroups = new List<TestGroup>();
        public IEnumerable<TestGroup> GetGroupsWhereThisIsMember() 
        {
            return _containerGroups;
        }
        public void SetGroupsWhereThisIsMember(IEnumerable<TestGroup> groups)
        {
            _containerGroups = groups.ToList();
        }

        private List<ISecurityUser> _users = new List<ISecurityUser>();
        public IEnumerable<ISecurityUser> GetUserMembers()
        {
            return _users;
        }
        public void SetUserMembers(IEnumerable<ISecurityUser> users)
        {
            _users = users.ToList();
        }

        internal void AddUser(TestUser user)
        {
            _users.Add(user);
        }
        internal void AddGroup(TestGroup group)
        {
            _groups.Add(group);
            group._containerGroups.Add(this);
        }

        internal void RemoveUser(TestUser user)
        {
            _users.Remove(user);
        }
        internal void RemoveGroup(TestGroup group)
        {
            _groups.Remove(group);
            group._containerGroups.Remove(this);
        }

        internal static int GetId(byte index)
        {
            return 100 + index;
        }

    }
}
