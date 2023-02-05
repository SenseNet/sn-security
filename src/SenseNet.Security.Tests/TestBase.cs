using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Diagnostics;
using SenseNet.Security.Data;
using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    public abstract class TestBase
    {
        private SnTrace.Operation _snTraceOperation;
        public void _StartTest(TestContext testContext)
        {
            //if (!SnTrace.SnTracers.Any(x => x is SnDebugViewTracer))
            //    SnTrace.SnTracers.Add(new SnDebugViewTracer());
            if (!SnTrace.SnTracers.Any(x => x is SnFileSystemTracer))
                SnTrace.SnTracers.Add(new SnFileSystemTracer());
            SnTrace.EnableAll();
//            SnTrace.SecurityQueue.Enabled = false;

            SnTrace.Test.Write("------------------------------------------------------------------------");
            _snTraceOperation =
                SnTrace.Test.StartOperation(
                    $"TESTMETHOD: {testContext.FullyQualifiedTestClassName}.{testContext.TestName}");
        }
        public void _FinishTest(TestContext testContext)
        {
            if (_snTraceOperation != null)
            {
                _snTraceOperation.Successful = true;
                _snTraceOperation.Dispose();
            }
            SnTrace.Flush();
        }

        /* ============================================================================================== */

        public int GetId(string name)
        {
            if (name[0] == 'G')
                return TestGroup.GetId(byte.Parse(name.Substring(1)));
            if (name[0] == 'U')
                return TestUser.GetId(byte.Parse(name.Substring(1)));
            if (name[0] == 'E')
                return TestEntity.GetId(byte.Parse(name.Substring(1)));
            throw new NotSupportedException("Invalid name: " + name);
        }
        internal string IdToName(int id)
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
        internal string ReplaceIds(string src)
        {
            var p = src.IndexOf('(');
            while (p >= 0)
            {
                var p1 = src.IndexOf(')', p);
                var s = src.Substring(p + 1, p1 - p - 1);
                var id = int.Parse(s);
                var name = IdToName(id);
                src = string.Concat(src.Substring(0, p), name, src.Substring(p1 + 1));
                p = src.IndexOf('(');
            }
            return src;
        }

        internal void ParsePermissions(string src, out ulong allowBits, out ulong denyBits)
        {
            //+_____-____++++
            const ulong mask = 1ul;
            allowBits = denyBits = 0;
            for (var i = src.Length - 1; i >= 0; i--)
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
        internal PermissionTypeBase[] GetPermissionTypes(string src)
        {
            var result = new List<PermissionTypeBase>();
            var index = 0;
            for (var i = src.Length - 1; i >= 0; i--)
            {
                if (src[i] != '_')
                    result.Add(PermissionTypeBase.GetPermissionTypeByIndex(index));
                index++;
            }
            return result.ToArray();
        }

        internal Context GetEmptyContext(TestUser currentUser)
        {
            //SecuritySystem.Instance.SecurityActivityQueue._setCurrentExecutionState(new CompletionState());
            //MemoryDataProvider.LastActivityId = 0;
            return GetEmptyContext(currentUser, new MemoryDataProvider(DatabaseStorage.CreateEmpty()));
        }
        internal Context GetEmptyContext(TestUser currentUser, ISecurityDataProvider dbProvider, TextWriter traceChannel = null)
        {
            var securitySystem = Context.StartTheSystem(
                dbProvider,
                DiTools.CreateDefaultMessageProvider(),
                traceChannel);
            return new Context(currentUser, securitySystem);
        }

        internal Dictionary<int, TestEntity> CreateRepository(SecurityContext context)
        {
            var u1 = TestUser.User1;
            var repository = new Dictionary<int, TestEntity>();

            CreateEntity(repository, context, "E1", null, u1);
            {
                CreateEntity(repository, context, "E2", "E1", u1);
                {
                    CreateEntity(repository, context, "E5", "E2", u1);
                    {
                        CreateEntity(repository, context, "E14", "E5", u1);
                        {
                            CreateEntity(repository, context, "E50", "E14", u1);
                            {
                                CreateEntity(repository, context, "E51", "E50", u1);
                                {
                                    CreateEntity(repository, context, "E52", "E51", u1);
                                }
                                CreateEntity(repository, context, "E53", "E50", u1);
                            }
                        }
                        CreateEntity(repository, context, "E15", "E5", u1);
                    }
                    CreateEntity(repository, context, "E6", "E2", u1);
                    {
                        CreateEntity(repository, context, "E16", "E6", u1);
                        CreateEntity(repository, context, "E17", "E6", u1);
                    }
                    CreateEntity(repository, context, "E7", "E2", u1);
                    {
                        CreateEntity(repository, context, "E18", "E7", u1);
                        CreateEntity(repository, context, "E19", "E7", u1);
                    }
                }
                CreateEntity(repository, context, "E3", "E1", u1);
                {
                    CreateEntity(repository, context, "E8", "E3", u1);
                    {
                        CreateEntity(repository, context, "E20", "E8", u1);
                        CreateEntity(repository, context, "E21", "E8", u1);
                        {
                            CreateEntity(repository, context, "E22", "E21", u1);
                            CreateEntity(repository, context, "E23", "E21", u1);
                            CreateEntity(repository, context, "E24", "E21", u1);
                            CreateEntity(repository, context, "E25", "E21", u1);
                            CreateEntity(repository, context, "E26", "E21", u1);
                            CreateEntity(repository, context, "E27", "E21", u1);
                            CreateEntity(repository, context, "E28", "E21", u1);
                            CreateEntity(repository, context, "E29", "E21", u1);
                        }
                    }
                    CreateEntity(repository, context, "E9", "E3", u1);
                    CreateEntity(repository, context, "E10", "E3", u1);
                }
                CreateEntity(repository, context, "E4", "E1", u1);
                {
                    CreateEntity(repository, context, "E11", "E4", u1);
                    CreateEntity(repository, context, "E12", "E4", u1);
                    {
                        CreateEntity(repository, context, "E30", "E12", u1);
                        {
                            CreateEntity(repository, context, "E31", "E30", u1);
                            {
                                CreateEntity(repository, context, "E33", "E31", u1);
                                CreateEntity(repository, context, "E34", "E31", u1);
                                {
                                    CreateEntity(repository, context, "E40", "E34", u1);
                                    CreateEntity(repository, context, "E43", "E34", u1);
                                    {
                                        CreateEntity(repository, context, "E44", "E43", u1);
                                        CreateEntity(repository, context, "E45", "E43", u1);
                                        CreateEntity(repository, context, "E46", "E43", u1);
                                        CreateEntity(repository, context, "E47", "E43", u1);
                                        CreateEntity(repository, context, "E48", "E43", u1);
                                        CreateEntity(repository, context, "E49", "E43", u1);
                                    }
                                }
                            }
                            CreateEntity(repository, context, "E32", "E30", u1);
                            {
                                CreateEntity(repository, context, "E35", "E32", u1);
                                {
                                    CreateEntity(repository, context, "E41", "E35", u1);
                                    {
                                        CreateEntity(repository, context, "E42", "E41", u1);
                                    }
                                }
                                CreateEntity(repository, context, "E36", "E32", u1);
                                {
                                    CreateEntity(repository, context, "E37", "E36", u1);
                                    {
                                        CreateEntity(repository, context, "E38", "E37", u1);
                                        CreateEntity(repository, context, "E39", "E37", u1);
                                    }
                                }
                            }
                        }
                    }
                    CreateEntity(repository, context, "E13", "E4", u1);
                }
            }
            return repository;
        }
        private void CreateEntity(Dictionary<int, TestEntity> repository, SecurityContext context,
            string name, string parentName, TestUser owner)
        {
            var entity = new TestEntity
            {
                Id = GetId(name),
                Name = name,
                OwnerId = owner?.Id ?? default,
                Parent = parentName == null ? null : repository[GetId(parentName)]
            };
            repository.Add(entity.Id, entity);
            context.CreateSecurityEntityAsync(entity.Id, entity.ParentId, entity.OwnerId, CancellationToken.None)
                .GetAwaiter().GetResult();
        }
        internal string EntityIdStructureToString(SecurityContext ctx)
        {
            var root = ctx.SecuritySystem.Cache.Entities.First().Value;
            while (root.Parent != null)
                root = root.Parent;

            var sb = new StringBuilder();
            sb.Append("{");
            EntityIdStructureToString(root, sb);
            sb.Append("}");
            return sb.ToString();
        }
        private void EntityIdStructureToString(SecurityEntity entity, StringBuilder sb)
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

        internal void SetMembership(SecurityContext context, string src)
        {
            // "U1:G1,G2|U2:G1"
            var membership = context.SecuritySystem.Cache.Membership;
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

        internal void SetAcl(SecurityContext context, string src)
        {
            // "+E1|Normal|+U1:____++++,+G1:____++++"
            var a = src.Split('|');
            var inherits = a[0][0] == '+';
            var b = a[0].Substring(1);
            if (b.Contains(','))
                throw new NotSupportedException("DO NOT PASS OWNER INFORMATION");
            var entityId = GetId(b);
            SetAcl(context, entityId, inherits, src.Substring(a[0].Length + 1));
        }
        private void SetAcl(SecurityContext context, int entityId, bool isInherited, string src)
        {
            // "+U1:____++++,+G1:____++++"
            var entity = context.GetSecurityEntity(entityId);

            var aclInfo = new AclInfo(entityId) { Entries = src.Split(',').Select(CreateAce).ToList() };

            var @break = false;
            var undoBreak = false;
            if (entity.IsInherited && !isInherited)
                @break = true;
            if (!entity.IsInherited && isInherited)
                undoBreak = true;
            context.SetAcls(
                new[] { aclInfo },
                @break ? new List<int> { entityId } : new List<int>(),
                undoBreak ? new List<int> { entityId } : new List<int>()
                );
        }
        private AceInfo CreateAce(string src)
        {
            // "Normal|+U1:____++++
            var segments = src.Split('|');

            Enum.TryParse<EntryType>(segments[0], true, out var entryType);

            var localOnly = segments[1][0] != '+';
            var a = segments[1].Substring(1).Split(':');

            ParsePermissions(a[1], out var allowBits, out var denyBits);
            return new AceInfo
            {
                EntryType = entryType,
                LocalOnly = localOnly,
                IdentityId = GetId(a[0]),
                AllowBits = allowBits,
                DenyBits = denyBits
            };
        }

        //============================================================================================================

        internal void CheckIntegrity(string testName, SecurityContext context)
        {
            CheckIntegrity(testName, context,
                context.SecuritySystem.DataProvider.LoadSecurityEntitiesAsync(CancellationToken.None)
                    .GetAwaiter().GetResult(),
                context.SecuritySystem.DataProvider.LoadAllGroupsAsync(CancellationToken.None)
                    .GetAwaiter().GetResult());
        }
        internal void CheckIntegrity(string testName, SecurityContext context, IEnumerable<StoredSecurityEntity> entities, IEnumerable<SecurityGroup> groups)
        {
            //TODO: REWRITE WHOLE CONSISTENCY CHECK
        }

        internal Dictionary<int, AclInfo> CollectAllAcls(SecurityContext ctx)
        {
            var result = ctx.SecuritySystem.Cache.Entities.Values.Where(e => e.Acl != null).Select(e => e.Acl).ToDictionary(e => e.EntityId);
            return result;
        }

        //============================================================================================================

        public void InitializeInMemoryMembershipStorage(Context ctx, string src)
        {
            var memoryDataProvider = (MemoryDataProvider)ctx.Security.SecuritySystem.DataProvider;
            // "G1:U1,G2,G3|G2:U2,G4,G5|G3:U3|G4:U4|G5:U5"
            var table = memoryDataProvider.Storage.Memberships;
            InitializeInMemoryMembershipTable(src, table);
        }
        public List<Membership> CreateInMemoryMembershipTable(Dictionary<int, SecurityGroup> groups)
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
        internal void InitializeInMemoryMembershipTable(string src, List<Membership> table)
        {
            table.Clear();
            // ReSharper disable once LoopCanBeConvertedToQuery
            foreach (var groupSrc in src.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var g = groupSrc.Split(new[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
                if (g.Length > 1)
                {
                    var groupId = GetId(g[0].Trim());
                    // ReSharper disable once LoopCanBeConvertedToQuery
                    foreach (var memberSrc in g[1].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                        table.Add(new Membership { GroupId = groupId, MemberId = GetId(memberSrc), IsUser = memberSrc[0] == 'U' });
                }
            }
        }

    }
}
