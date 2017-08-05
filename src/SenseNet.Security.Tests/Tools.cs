using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;
using SenseNet.Security;
using SenseNet.Security.Data;
using SenseNet.Security.EF6SecurityStore;
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
        internal static string IdToName(int id)
        {
            var category = id / 100;
            var value = id % 100;
            switch (category)
            {
                case 0:
                    return "E" + value;
                case 1:
                    return "G" + value;
                case 2:
                    return "U" + value;
                default:
                    throw new NotSupportedException("##");
            }

        }
        internal static string ReplaceIds(string src)
        {
            int p = src.IndexOf('(');
            while (p >= 0)
            {
                var p1 = src.IndexOf(')', p);
                var s = src.Substring(p + 1, p1 - p - 1);
                var id = int.Parse(s);
                var name = Tools.IdToName(id);
                src = string.Concat(src.Substring(0, p), name, src.Substring(p1 + 1));
                p = src.IndexOf('(');
            }
            return src;
        }

        internal static void ParsePermissions(string src, out ulong allowBits, out ulong denyBits)
        {
            //+_____-____++++
            var mask = 1ul;
            allowBits = denyBits = 0;
            for (int i = src.Length - 1; i >= 0; i--)
            {
                var c = src[i];
                if (c == '+')
                    allowBits |= mask << src.Length - i - 1;
                if (c == '-')
                    denyBits |= mask << src.Length - i - 1;
            }
        }

        /// <summary>
        /// Returns resolved permission types by the passed source string like this: "______________+"
        /// </summary>
        /// <param name="src">Use like tis: "______________+"</param>
        /// <returns>PermissionType[]</returns>
        internal static PermissionTypeBase[] GetPermissionTypes(string src)
        {
            var result = new List<PermissionTypeBase>();
            var index = 0;
            for (int i = src.Length - 1; i >= 0; i--)
            {
                if (src[i] != '_')
                    result.Add(PermissionType.GetPermissionTypeByIndex(index));
                index++;
            }
            return result.ToArray();
        }

        internal static StoredAce[] PeekEntriesFromTestDatabase(int entityId, MemoryDataProvider database)
        {
            return new MemoryDataProviderAccessor(database).Storage.Aces.Where(x => x.EntityId == entityId).ToArray();
        }
        internal static StoredAce[] PeekEntriesFromTestDatabase(int entityId, SecurityStorage database)
        {
            var entries = database.EFEntries.Where(x => x.EFEntityId == entityId).ToArray();
            return entries.Select(a => new StoredAce
            {
                EntityId = a.EFEntityId,
                IdentityId = a.IdentityId,
                LocalOnly = a.LocalOnly,
                AllowBits = Convert.ToUInt64(a.AllowBits),
                DenyBits = Convert.ToUInt64(a.DenyBits),
            }).ToArray();
        }

        internal static Context GetEmptyContext(TestUser currentUser)
        {
            SecurityActivityQueue._setCurrentExecutionState(new CompletionState());
            MemoryDataProvider.LastActivityId = 0;
            return GetEmptyContext(currentUser, new MemoryDataProvider(DatabaseStorage.CreateEmpty()));
        }
        internal static Context GetEmptyContext(TestUser currentUser, ISecurityDataProvider dbProvider)
        {
            Context.StartTheSystem(dbProvider, new DefaultMessageProvider());
            return new Context(currentUser);
        }

        internal static Dictionary<int, TestEntity> CreateRepository(TestSecurityContext context)
        {
            TestEntity e;
            var u1 = TestUser.User1;
            var repository = new Dictionary<int, TestEntity>();

            e = CreateEntity(repository, context, "E1", null, u1);
            {
                e = CreateEntity(repository, context, "E2", "E1", u1);
                {
                    e = CreateEntity(repository, context, "E5", "E2", u1);
                    {
                        e = CreateEntity(repository, context, "E14", "E5", u1);
                        {
                            e = CreateEntity(repository, context, "E50", "E14", u1);
                            {
                                e = CreateEntity(repository, context, "E51", "E50", u1);
                                {
                                    e = CreateEntity(repository, context, "E52", "E51", u1);
                                }
                                e = CreateEntity(repository, context, "E53", "E50", u1);
                            }
                        }
                        e = CreateEntity(repository, context, "E15", "E5", u1);
                    }
                    e = CreateEntity(repository, context, "E6", "E2", u1);
                    {
                        e = CreateEntity(repository, context, "E16", "E6", u1);
                        e = CreateEntity(repository, context, "E17", "E6", u1);
                    }
                    e = CreateEntity(repository, context, "E7", "E2", u1);
                    {
                        e = CreateEntity(repository, context, "E18", "E7", u1);
                        e = CreateEntity(repository, context, "E19", "E7", u1);
                    }
                }
                e = CreateEntity(repository, context, "E3", "E1", u1);
                {
                    e = CreateEntity(repository, context, "E8", "E3", u1);
                    {
                        e = CreateEntity(repository, context, "E20", "E8", u1);
                        e = CreateEntity(repository, context, "E21", "E8", u1);
                        {
                            e = CreateEntity(repository, context, "E22", "E21", u1);
                            e = CreateEntity(repository, context, "E23", "E21", u1);
                            e = CreateEntity(repository, context, "E24", "E21", u1);
                            e = CreateEntity(repository, context, "E25", "E21", u1);
                            e = CreateEntity(repository, context, "E26", "E21", u1);
                            e = CreateEntity(repository, context, "E27", "E21", u1);
                            e = CreateEntity(repository, context, "E28", "E21", u1);
                            e = CreateEntity(repository, context, "E29", "E21", u1);
                        }
                    }
                    e = CreateEntity(repository, context, "E9", "E3", u1);
                    e = CreateEntity(repository, context, "E10", "E3", u1);
                }
                e = CreateEntity(repository, context, "E4", "E1", u1);
                {
                    e = CreateEntity(repository, context, "E11", "E4", u1);
                    e = CreateEntity(repository, context, "E12", "E4", u1);
                    {
                        e = CreateEntity(repository, context, "E30", "E12", u1);
                        {
                            e = CreateEntity(repository, context, "E31", "E30", u1);
                            {
                                e = CreateEntity(repository, context, "E33", "E31", u1);
                                e = CreateEntity(repository, context, "E34", "E31", u1);
                                {
                                    e = CreateEntity(repository, context, "E40", "E34", u1);
                                    e = CreateEntity(repository, context, "E43", "E34", u1);
                                    {
                                        e = CreateEntity(repository, context, "E44", "E43", u1);
                                        e = CreateEntity(repository, context, "E45", "E43", u1);
                                        e = CreateEntity(repository, context, "E46", "E43", u1);
                                        e = CreateEntity(repository, context, "E47", "E43", u1);
                                        e = CreateEntity(repository, context, "E48", "E43", u1);
                                        e = CreateEntity(repository, context, "E49", "E43", u1);
                                    }
                                }
                            }
                            e = CreateEntity(repository, context, "E32", "E30", u1);
                            {
                                e = CreateEntity(repository, context, "E35", "E32", u1);
                                {
                                    e = CreateEntity(repository, context, "E41", "E35", u1);
                                    {
                                        e = CreateEntity(repository, context, "E42", "E41", u1);
                                    }
                                }
                                e = CreateEntity(repository, context, "E36", "E32", u1);
                                {
                                    e = CreateEntity(repository, context, "E37", "E36", u1);
                                    {
                                        e = CreateEntity(repository, context, "E38", "E37", u1);
                                        e = CreateEntity(repository, context, "E39", "E37", u1);
                                    }
                                }
                            }
                        }
                    }
                    e = CreateEntity(repository, context, "E13", "E4", u1);
                }
            }
            return repository;
        }
        private static TestEntity CreateEntity(Dictionary<int, TestEntity> repository, TestSecurityContext context, string name, string parentName, TestUser owner)
        {
            var entity = new TestEntity
            {
                Id = GetId(name),
                Name = name,
                OwnerId = owner == null ? default(int) : owner.Id,
                Parent = parentName == null ? null : repository[GetId(parentName)],
            };
            repository.Add(entity.Id, entity);
            context.CreateSecurityEntity(entity);
            return entity;
        }
        internal static string EntityIdStructureToString(SecurityContext ctx)
        {
            var root = ctx.Cache.Entities.First().Value;
            while (root.Parent != null)
                root = root.Parent;

            var sb = new StringBuilder();
            sb.Append("{");
            EntityIdStructureToString(root, sb);
            sb.Append("}");
            return sb.ToString();
        }
        private static void EntityIdStructureToString(SecurityEntity entity, StringBuilder sb)
        {
            sb.Append(IdToName(entity.Id));
            if (entity.Children != null && entity.Children.Count > 0)
            {
                sb.Append("{");
                foreach (var child in entity.Children.OrderBy(x => x.Id))
                    EntityIdStructureToString(child, sb);
                sb.Append("}");
            }
        }

        internal static void SetMembership(SecurityContext context, string src)
        {
            // "U1:G1,G2|U2:G1"
            var membership = context.Cache.Membership;
            membership.Clear();
            foreach (var userRecord in src.Split('|'))
            {
                var ur = userRecord.Split(':');
                var userName = ur[0].Substring(1);
                var userId = TestUser.GetId(byte.Parse(userName));
                var groupIds = ur[1].Split(',').Select(x => TestGroup.GetId(byte.Parse(x.Substring(1)))).ToList();
                membership.Add(userId, groupIds);
            }
        }

        internal static void SetAcl(SecurityContext context, string src)
        {
            // "+E1|+U1:____++++,+G1:____++++"
            var a = src.Split('|');
            var inherits = a[0][0] == '+';
            var b = a[0].Substring(1);
            if (b.Contains(','))
                throw new NotSupportedException("DO NOT PASS OWNER INFORMATION");
            var entityId = GetId(b);
            SetAcl(context, entityId, inherits, a[1]);
        }
        private static void SetAcl(SecurityContext context, TestEntity entity, string src)
        {
            var secEntity = context.GetSecurityEntity(entity.Id);
            SetAcl(context, entity.Id, secEntity.IsInherited, src);
        }
        private static void SetAcl(SecurityContext context, int entityId, bool isInherited, string src)
        {
            // "+U1:____++++,+G1:____++++"
            var entity = context.GetSecurityEntity(entityId);

            var aclInfo = new AclInfo(entityId) { Entries = src.Split(',').Select(x => CreateAce(x)).ToList() };

            var emptyGuidArray = new List<int>();
            var breaked = false;
            var unbreaked = false;
            if (entity.IsInherited && !isInherited)
                breaked = true;
            if (!entity.IsInherited && isInherited)
                unbreaked = true;
            context.SetAcls(
                new[] { aclInfo },
                breaked ? new List<int> { entityId } : new List<int>(),
                unbreaked ? new List<int> { entityId } : new List<int>()
                );
            return;
        }
        private static AceInfo CreateAce(string src)
        {
            // "+U1:____++++
            var localOnly = src[0] != '+';
            var a = src.Substring(1).Split(':');
            ulong allowBits;
            ulong denyBits;
            Tools.ParsePermissions(a[1], out allowBits, out denyBits);
            return new AceInfo
            {
                LocalOnly = localOnly,
                IdentityId = GetId(a[0]),
                AllowBits = allowBits,
                DenyBits = denyBits
            };
        }

        //============================================================================================================

        internal static void CheckIntegrity(string testName, SecurityContext context)
        {
            CheckIntegrity(testName, context, context.DataProvider.LoadSecurityEntities(), context.DataProvider.LoadAllGroups());
        }
        internal static void CheckIntegrity(string testName, SecurityContext context, IEnumerable<StoredSecurityEntity> entities, IEnumerable<SecurityGroup> groups)
        {
            //TODO: REWRITE WHOLE CONSISTENY CHECK
            return;
        }

        internal static Dictionary<int, AclInfo> CollectAllAcls(SecurityContext ctx)
        {
            var result = ctx.Cache.Entities.Values.Where(e => e.Acl != null).Select(e => e.Acl).ToDictionary(e => e.EntityId);
            return result;
        }

        //============================================================================================================

        public static void InitializeInMemoryMembershipStorage(string src)
        {
            // "G1:U1,G2,G3|G2:U2,G4,G5|G3:U3|G4:U4|G5:U5"
            var table = MemoryDataProvider.Storage.Memberships;
            InitializeInMemoryMembershipTable(src, table);
        }
        public static List<Membership> CreateInMemoryMembershipTable(string src)
        {
            // example: "G1:U1,U2|G2:U3,U4|G3:U1,U3|G4:U4|G5:U5"
            var table = new List<Membership>();
            InitializeInMemoryMembershipTable(src, table);
            return table;
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
        internal static void InitializeInMemoryMembershipTable(string src, List<Membership> table)
        {
            table.Clear();
            foreach (var groupSrc in src.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var g = groupSrc.Split(new[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
                if (g.Length > 1)
                {
                    var groupId = GetId(g[0].Trim());
                    foreach (var memberSrc in g[1].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                        table.Add(new Membership { GroupId = groupId, MemberId = GetId(memberSrc), IsUser = memberSrc[0] == 'U' });
                }
            }
        }

    }
}
