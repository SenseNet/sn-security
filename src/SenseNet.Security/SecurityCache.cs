using System;
using System.Collections.Generic;
using System.Linq;

namespace SenseNet.Security
{
    /// <summary>
    /// Internal class holding the in-memory representation of all the entity and membership data in the system.
    /// </summary>
    internal class SecurityCache
    {
        internal IDictionary<int, SecurityEntity> Entities { get; private set; }  // EntityId --> SecurityEntity
        internal IDictionary<int, SecurityGroup> Groups { get; private set; }     // GroupId  --> Group
        internal Dictionary<int, List<int>> Membership { get; private set; }      // UserId   --> list of ContainerIds

        private readonly ISecurityDataProvider _dataProvider;
        private SecuritySystem _securitySystem;
        public SecurityCache(SecuritySystem securitySystem)
        {
            _dataProvider = securitySystem.SecurityDataProvider;
            _securitySystem = securitySystem;
        }
        internal void Initialize()
        {
            Load(_dataProvider);
        }
        internal void Reset(ISecurityDataProvider dataProvider)
        {
            Load(dataProvider);
        }
        internal void Load(ISecurityDataProvider dataProvider)
        {
            var dataHandler = _securitySystem.DataHandler;

            var entities = dataHandler.LoadSecurityEntities(dataProvider);
            var aclTable = dataHandler.LoadAcls(dataProvider, entities);
            BuildAcls(entities, aclTable);

            Entities = entities;
            Groups = dataHandler.LoadAllGroups(dataProvider);
            Membership = FlattenUserMembership(Groups);
        }

        private void BuildAcls(IDictionary<int, SecurityEntity> entities, Dictionary<int, AclInfo> aclTable)
        {
            foreach (var acl in aclTable.Values)
            {
                if (entities.TryGetValue(acl.EntityId, out var entity))
                    entity.SetAclSafe(acl);
            }
            foreach (var entity in entities.Values.Where(e => !e.IsInherited && !e.HasExplicitAcl))
            {
                entity.SetAclSafe(new AclInfo(entity.Id));
            }
        }

        internal Dictionary<int, List<int>> FlattenUserMembership(IDictionary<int, SecurityGroup> groups)
        {
            var allUsers = new Dictionary<int, List<int>>();
            foreach (var group in groups.Values)
            {
                var flattenedGroups = new List<SecurityGroup>();
                FlattenGroupMembership(group, flattenedGroups);
                foreach (var userId in group.UserMemberIds)
                {
                    var user = EnsureUser(userId, allUsers);
                    foreach (var flattenedGroup in flattenedGroups)
                        if (!user.Contains(flattenedGroup.Id))
                            user.Add(flattenedGroup.Id);
                }
            }
            return allUsers;
        }
        private void FlattenGroupMembership(SecurityGroup group, List<SecurityGroup> flattenedGroups)
        {
            // avoid infinite loop because of circular references
            if (flattenedGroups.Contains(group))
                return;

            flattenedGroups.Add(group);

            // recursion
            foreach (var parentGroup in group.ParentGroups)
                FlattenGroupMembership(parentGroup, flattenedGroups);
        }
        private List<int> EnsureUser(int userId, Dictionary<int, List<int>> users)
        {
            if (!users.TryGetValue(userId, out var user))
            {
                user = new List<int>();
                users.Add(userId, user);
            }
            return user;
        }

        public IEnumerable<long> GetMembershipForConsistencyCheck()
        {
            var result = new List<long>();
            foreach (var group in Groups.Values)
            {
                var groupBase = Convert.ToInt64(group.Id) << 32;
                result.AddRange(group.UserMemberIds.Select(u => groupBase + u));
                result.AddRange(group.Groups.Select(g => groupBase + g.Id));
            }
            return result;
        }
        public void GetFlatteningForConsistencyCheck(out IEnumerable<long> missingInFlattening, out IEnumerable<long> unknownInFlattening)
        {
            var actual = ConvertFlattenedUserMembershipToControlData(Membership).ToArray();
            var expected = ConvertFlattenedUserMembershipToControlData(FlattenUserMembership(Groups)).ToArray();
            missingInFlattening = expected.Except(actual).ToArray();
            unknownInFlattening = actual.Except(expected).ToArray();
        }
        private IEnumerable<long> ConvertFlattenedUserMembershipToControlData(Dictionary<int, List<int>> membership)
        {
            var result = new List<long>(membership.Count * 2);
            foreach (var item in membership)
            {
                var group = Convert.ToInt64(item.Key) << 32;
                foreach (var member in item.Value)
                    result.Add(group + member);
            }
            return result;
        }

        /*========================================================================= In memory membership API */

        //TODO: When allowing parallel activities in the future, take care of thread safety!

        internal void AddMembers(int groupId, IEnumerable<int> groupIds, IEnumerable<int> userIds, IEnumerable<int> parentGroupIds)
        {
            // place the new relations, skip old ones.
            var group = EnsureGroup(groupId);
            if (userIds != null)
            {
                foreach (var userId in userIds)
                {
                    Flattener.AddUserToGroup(userId, group, Membership);
                    if (!group.UserMemberIds.Contains(userId))
                        group.UserMemberIds.Add(userId);
                }
            }
            if (groupIds != null)
            {
                foreach (var childGroupId in groupIds)
                {
                    var childGroup = EnsureGroup(childGroupId);
                    Flattener.AddGroupToGroup(childGroup, group, Membership);
                    AddRelation(group.Groups, childGroup);
                    AddRelation(childGroup.ParentGroups, group);
                }
            }
            if (parentGroupIds != null)
            {
                foreach (var parentGroupId in parentGroupIds)
                {
                    var parentGroup = EnsureGroup(parentGroupId);
                    Flattener.AddGroupToGroup(group, parentGroup, Membership);
                    AddRelation(group.ParentGroups, parentGroup);
                    AddRelation(parentGroup.Groups, group);
                }
            }
        }
        private SecurityGroup EnsureGroup(int groupId)
        {
            if (!Groups.TryGetValue(groupId, out var group))
            {
                group = new SecurityGroup(groupId);
                Groups.Add(groupId, group);
            }
            return group;
        }
        private void AddRelation(List<SecurityGroup> container, SecurityGroup item)
        {
            if (container.All(x => x.Id != item.Id))
                container.Add(item);
        }

        internal void AddUserToGroups(int userId, IEnumerable<int> parentGroupIds)
        {
            if (parentGroupIds == null)
                return;

            // place the new relations, skip old ones.
            foreach (var parentGroupId in parentGroupIds)
            {
                var parentGroup = EnsureGroup(parentGroupId);
                if (!parentGroup.UserMemberIds.Contains(userId))
                    parentGroup.UserMemberIds.Add(userId);
                Flattener.AddUserToGroup(userId, parentGroup, Membership);
            }
        }

        internal void DeleteUser(SecurityContext context, int userId)
        {
            // refresh flattening
            Flattener.DeleteUser(userId, Membership);

            // delete from Groups
            foreach (var group in Groups.Values)
                group.UserMemberIds.Remove(userId);

            // delete ACEs & empty ACLs
            SecurityEntity.RemoveIdentityRelatedAces(context, userId);
        }

        internal void DeleteSecurityGroup(SecurityContext context, int groupId)
        {
            // delete from Groups
            if (Groups.TryGetValue(groupId, out var group))
            {
                // getting support lists
                var allUsers = Flattener.GetAllUserIds(group);
                var allParents = Flattener.GetAllParentGroupIdsInclusive(group);

                // remove references
                foreach (var g in group.Groups)
                    g.ParentGroups.Remove(group);
                foreach (var g in group.ParentGroups)
                    g.Groups.Remove(group);
                Groups.Remove(groupId);

                // refresh flattening with support lists
                Flattener.DeleteGroup(group, allUsers, allParents, Groups, Membership);
            }

            // delete ACEs & empty ACLs
            SecurityEntity.RemoveIdentityRelatedAces(context, groupId);
        }

        internal void DeleteIdentities(SecurityContext context, IEnumerable<int> identityIds)
        {
            foreach (var identityId in identityIds)
            {
                // delete from Groups
                if (Groups.TryGetValue(identityId, out var group))
                {
                    // identityId is a groupId
                    var allUsers = Flattener.GetAllUserIds(group);
                    var allParents = Flattener.GetAllParentGroupIdsInclusive(group);

                    foreach (var g in group.Groups)
                        g.ParentGroups.Remove(group);
                    foreach (var g in group.ParentGroups)
                        g.Groups.Remove(group);
                    Groups.Remove(identityId);

                    // refresh flattening with support lists
                    Flattener.DeleteGroup(group, allUsers, allParents, Groups, Membership);
                }
                else
                {
                    // identityId is a userId or an unknown item
                    Flattener.DeleteUser(identityId, Membership);

                    foreach (var grp in Groups.Values)
                        grp.UserMemberIds.Remove(identityId);
                }

                // delete Aces & empty ACLs
                SecurityEntity.RemoveIdentityRelatedAces(context, identityId);
            }
        }

        internal void RemoveMembers(int groupId, IEnumerable<int> groupIds, IEnumerable<int> userIds, IEnumerable<int> parentGroupIds)
        {
            if (!Groups.TryGetValue(groupId, out var group))
                return;


            if (userIds != null)
            {
                foreach (var userId in userIds)
                {
                    group.UserMemberIds.Remove(userId);
                    Flattener.RemoveUserFromGroup(userId, group, Membership, Groups);
                }
            }


            // support list for refreshing flattened membership
            List<int> allUsers;
            List<int> allParents;

            if (groupIds != null)
            {
                var memberGroups = group.Groups.Where(x => groupIds.Contains(x.Id)).ToArray();
                foreach (var memberGroup in memberGroups)
                {
                    allUsers = Flattener.GetAllUserIds(memberGroup);
                    allParents = Flattener.GetAllParentGroupIdsInclusive(memberGroup);

                    memberGroup.ParentGroups.Remove(group);
                    group.Groups.Remove(memberGroup);

                    // refresh flattening
                    Flattener.DeleteGroup(memberGroup, allUsers, allParents, Groups, Membership);
                }
            }
            if (parentGroupIds != null)
            {
                var parentGroups = group.ParentGroups.Where(x => parentGroupIds.Contains(x.Id)).ToArray();
                foreach (var parentGroup in parentGroups)
                {
                    allUsers = Flattener.GetAllUserIds(parentGroup);
                    allParents = Flattener.GetAllParentGroupIdsInclusive(parentGroup);

                    parentGroup.Groups.Remove(group);
                    group.ParentGroups.Remove(parentGroup);

                    // refresh flattening
                    Flattener.DeleteGroup(parentGroup, allUsers, allParents, Groups, Membership);
                }
            }
        }

        internal void RemoveUserFromGroups(int userId, IEnumerable<int> parentGroupIds)
        {
            if (parentGroupIds == null)
                return;

            foreach (var parentGroupId in parentGroupIds)
            {
                if (Groups.TryGetValue(parentGroupId, out var group))
                {
                    var allUsers = Flattener.GetAllUserIds(group);
                    var allParents = Flattener.GetAllParentGroupIdsInclusive(group);

                    group.UserMemberIds.Remove(userId);

                    // refresh flattening
                    Flattener.DeleteGroup(group, allUsers, allParents, Groups, Membership);
                }
            }
        }

        internal bool IsInGroup(int memberId, int groupId)
        {
            // if it is a user: first look for the id in the flattened user --> groups collection
            if (Membership.TryGetValue(memberId, out var flattenedGroups))
                return flattenedGroups.Contains(groupId);

            // if it is a group: search in the group graph
            if (Groups.TryGetValue(memberId, out var group))
                return Flattener.GetAllParentGroupIdsExclusive(group).Contains(groupId);

            return false;
        }

        internal int[] GetGroups(int userId)
        {
            return Membership.TryGetValue(userId, out var flattenedGroups)
                ? flattenedGroups.ToArray()
                : new int[0];
        }

        internal IEnumerable<int> GetAllUsersInGroup(SecurityGroup group)
        {
            return Flattener.GetAllUserIds(group);
        }
        internal IEnumerable<int> GetAllParentGroupIds(SecurityGroup group)
        {
            return Flattener.GetAllParentGroupIdsExclusive(group);
        }

        /*=================================================================================== Flattener */

        private FlattenerClass Flattener = new FlattenerClass();

        private class FlattenerClass
        {
            internal void AddUserToGroup(int userId, SecurityGroup parentGroup, Dictionary<int, List<int>> usersTable)
            {
                // collect all relevant groupId from the parent axis
                var allParentGroupIds = GetAllParentGroupIdsInclusive(parentGroup);

                // ensure user
                if (!usersTable.TryGetValue(userId, out var user))
                {
                    user = new List<int>();
                    usersTable.Add(userId, user);
                }

                // complete the user (distinct groupId list) with the relevant groups (allParentGroupIds)
                foreach (var parentGroupId in allParentGroupIds)
                    if (!user.Contains(parentGroupId))
                        user.Add(parentGroupId);
            }

            internal void AddGroupToGroup(SecurityGroup group, SecurityGroup parentGroup, Dictionary<int, List<int>> usersTable)
            {
                var allUserIds = GetAllUserIds(group);
                var allParentGroupIds = GetAllParentGroupIdsInclusive(parentGroup);
                foreach (var userId in allUserIds)
                {
                    if (!usersTable.TryGetValue(userId, out var user))
                    {
                        user = new List<int>();
                        usersTable.Add(userId, user);
                    }

                    foreach (var parentGroupId in allParentGroupIds)
                        if (!user.Contains(parentGroupId))
                            user.Add(parentGroupId);
                }
            }

            internal void DeleteUser(int userId, Dictionary<int, List<int>> usersTable)
            {
                usersTable.Remove(userId);
            }

            internal void RemoveUserFromGroup(int userId, SecurityGroup parentGroup, Dictionary<int, List<int>> usersTable, IDictionary<int, SecurityGroup> groupsTable)
            {
                var allParents = GetAllParentGroupIdsInclusive(parentGroup);
                RemoveUserFromGroup(userId, allParents, usersTable, groupsTable);
            }

            // ReSharper disable once UnusedParameter.Local
            internal void DeleteGroup(SecurityGroup deletedGroup, List<int> allUsers, List<int> allParents, IDictionary<int, SecurityGroup> groupsTable, Dictionary<int, List<int>> usersTable)
            {
                foreach (var userId in allUsers)
                    RemoveUserFromGroup(userId, allParents, usersTable, groupsTable);
            }

            private void RemoveUserFromGroup(int userId, List<int> allParents, Dictionary<int, List<int>> usersTable, IDictionary<int, SecurityGroup> groupsTable)
            {
                // get user record (what groups member of?)
                if (!usersTable.TryGetValue(userId, out var user))
                    return;

                // clone for a support list
                var origUser = user.ToList();

                // remove from all parents (forget groupId from user record)
                user.RemoveAll(allParents.Contains);

                // rebuild all existing groups
                foreach (var groupId in origUser)
                {
                    if (!groupsTable.TryGetValue(groupId, out var group))
                        continue;

                    // skip if the group doesn't contain the user explicitly
                    if (group.UserMemberIds.Contains(userId))
                    {
                        // write back into every parent group
                        var allParentIds = GetAllParentGroupIdsInclusive(group);
                        foreach (var parentId in allParentIds)
                            if (!user.Contains(parentId))
                                user.Add(parentId);
                    }
                }

                // delete user if empty
                if (user.Count == 0)
                    usersTable.Remove(userId);
            }

            /// <summary>
            /// Gathers all the parent groups of a group. The initial group WILL be in the list.
            /// </summary>
            internal List<int> GetAllParentGroupIdsInclusive(SecurityGroup group)
            {
                var allParentGroups = new List<SecurityGroup>();
                CollectAllParentGroupsInclusive(group, allParentGroups);
                return allParentGroups.Select(x => x.Id).ToList();
            }
            private void CollectAllParentGroupsInclusive(SecurityGroup group, List<SecurityGroup> allParentGroups)
            {
                // avoid infinite loop because of circular reference
                if (allParentGroups.Contains(group))
                    return;
                // stop if there isn't any parent
                if (group.ParentGroups == null)
                    return;

                // collect
                allParentGroups.Add(group);

                // do recursion
                foreach (var parentGroup in group.ParentGroups)
                    CollectAllParentGroupsInclusive(parentGroup, allParentGroups);
            }
            /// <summary>
            /// Gathers all the parent groups of a group. The initial group 
            /// will be in the list ONLY if there is a circle in the graph.
            /// </summary>
            internal List<int> GetAllParentGroupIdsExclusive(SecurityGroup group)
            {
                var allParentGroups = new List<SecurityGroup>();
                CollectAllParentGroupsExclusive(group, allParentGroups);
                return allParentGroups.Select(x => x.Id).ToList();
            }
            private void CollectAllParentGroupsExclusive(SecurityGroup group, List<SecurityGroup> allParentGroups)
            {
                // stop if there are no parents
                if (group.ParentGroups == null)
                    return;

                // do recursion, but avoid infinite loop
                foreach (var parentGroup in group.ParentGroups.Where(p => !allParentGroups.Contains(p)))
                {
                    allParentGroups.Add(parentGroup);
                    CollectAllParentGroupsExclusive(parentGroup, allParentGroups);
                }
            }

            internal List<int> GetAllUserIds(SecurityGroup group)
            {
                var allChildGroups = new List<SecurityGroup>();
                CollectAllChildGroups(group, allChildGroups);

                var userIds = new List<int>();
                foreach (var g in allChildGroups)
                    foreach (var u in g.UserMemberIds)
                        if (!userIds.Contains(u))
                            userIds.Add(u);
                return userIds;
            }
            private void CollectAllChildGroups(SecurityGroup group, List<SecurityGroup> allChildGroups)
            {
                // avoid infinite loop because of circular reference
                if (allChildGroups.Contains(group))
                    return;
                // stop if there isn't any parent
                if (group.Groups == null)
                    return;

                // collect
                allChildGroups.Add(group);

                // do recursion
                foreach (var childGroup in group.Groups)
                    CollectAllChildGroups(childGroup, allChildGroups);
            }
        }

    }
}
