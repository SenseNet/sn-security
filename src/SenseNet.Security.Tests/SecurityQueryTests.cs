using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class SecurityQueryTests
    {
        #region Infrastructure
        private Context CurrentContext { get; set; }

        public TestContext TestContext { get; set; }

        [TestInitialize]
        public void StartTest()
        {
            CurrentContext = Tools.GetEmptyContext(TestUser.User1);
            CreatePlayground();
        }
        #endregion

        [TestMethod]
        public void Linq_Root_Entities_All()
        {
            var ctx = CurrentContext.Security;

            // ACTION
            var result = SecurityQuery.All(ctx).GetEntities(_rootEntityId);

            // ASSERT
            var ids = GetSortedIds(result);
            // if the boundary and the count is the same, the sequences are equal
            Assert.AreEqual(_repository.Count, ids.Length);
            Assert.AreEqual(_repository.Keys.Min(), ids[0]);
            Assert.AreEqual(_repository.Keys.Max(), ids[ids.Length - 1]);
        }
        [TestMethod]
        public void Linq_Root_Entities_SecurityRelated()
        {
            var ctx = CurrentContext.Security;
            const string expected = "2,4,5,10,11,12,15,16,20,22,25,28,32,34,35,36,37,41";

            var result = SecurityQuery.All(ctx).GetEntities(_rootEntityId).Where(e => e.Acl != null);

            Assert.AreEqual(expected, GetSortedIdString(result));
        }
        [TestMethod]
        public void Linq_Root_Entities_AllBreaks()
        {
            var ctx = CurrentContext.Security;
            const string expected = "22,34,35,36,37,41";

            var result = SecurityQuery.All(ctx).GetEntities(_rootEntityId).Where(e => !e.IsInherited);

            Assert.AreEqual(expected, GetSortedIdString(result));
        }
        [TestMethod]
        public void Linq_Root_Identities_AllExisting()
        {
            var ctx = CurrentContext.Security;
            const string expected = "101,102,201,202,203";

            var result = SecurityQuery.All(ctx).GetEntities(_rootEntityId)
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Select(e => e.IdentityId)
                .Distinct();

            Assert.AreEqual(expected, GetSortedIdString(result));
        }

        [TestMethod]
        public void Linq_All_Entities()
        {
            var ctx = CurrentContext.Security;
            const string expected = "1,4,12,30,32,35,36,37,38,39,41,42";

            // ACTION
            var result = SecurityQuery.All(ctx).GetEntities(Id("E32"));

            // ASSERT
            Assert.AreEqual(expected, GetSortedIdString(result.Select(e => e.Id)));
        }

        [TestMethod]
        public void Linq_Parent_Entities()
        {
            var ctx = CurrentContext.Security;
            const string expected = "30,12,4,1";

            // ACTION
            var result = SecurityQuery.ParentChain(ctx).GetEntities(Id("E32"));

            // ASSERT
            Assert.AreEqual(expected, GetIdString(result.Select(e => e.Id)));
        }

        [TestMethod]
        public void Linq_Subtree_Entities()
        {
            var ctx = CurrentContext.Security;
            const string expected = "32,35,36,37,38,39,41,42";

            // ACTION
            var result = SecurityQuery.Subtree(ctx).GetEntities(Id("E32"), BreakOptions.StopAtParentBreak);

            // ASSERT
            Assert.AreEqual(expected, GetSortedIdString(result.Select(e => e.Id)));
        }

        [TestMethod]
        public void Linq_Parent_Entity_StopAtBreak()
        {
            var ctx = CurrentContext.Security;
            ctx.CreateAclEditor()
                .BreakInheritance(Id("E4"))
                .Apply();
            const string expected = "30,12,4";

            var result = SecurityQuery.ParentChain(ctx).GetEntities(Id("E32"),
                BreakOptions.StopAtParentBreak);

            Assert.AreEqual(expected, GetIdString(result.Select(e => e.Id)));
        }
        [TestMethod]
        public void Linq_Subtree_Entity_StopAtBreaks()
        {
            var ctx = CurrentContext.Security;
            const string expected = "30,31,32,33";

            var result = SecurityQuery.Subtree(ctx).GetEntities(Id("E30"),
                BreakOptions.StopAtSubtreeBreaks);

            Assert.AreEqual(expected, GetSortedIdString(result.Select(e => e.Id)));
        }
        [TestMethod]
        public void Linq_All_Entity_StopAtBreaks()
        {
            var ctx = CurrentContext.Security;
            ctx.CreateAclEditor()
                .BreakInheritance(Id("E4"))
                .Apply();
            const string expected = "4,12,30,31,32,33";

            var result = SecurityQuery.All(ctx).GetEntities(Id("E30"),
                BreakOptions.StopAtParentBreak | BreakOptions.StopAtSubtreeBreaks);

            Assert.AreEqual(expected, GetSortedIdString(result.Select(e => e.Id)));
        }


        [TestMethod]
        public void Linq_All_Identities_AllExisting()
        {
            var ctx = CurrentContext.Security;
            AddPermissionsForIdentityTests(ctx);
            const string expected = "101,106,107,201,202,203,204,205";

            var result = SecurityQuery.All(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Select(e => e.IdentityId)
                .Distinct();

            Assert.AreEqual(expected, GetSortedIdString(result));
        }
        [TestMethod]
        public void Linq_Parent_Identities_AllExisting()
        {
            var ctx = CurrentContext.Security;
            AddPermissionsForIdentityTests(ctx);
            const string expected = "101,106,201,203,204";

            var result = SecurityQuery.ParentChain(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Select(e => e.IdentityId)
                .Distinct();

            Assert.AreEqual(expected, GetSortedIdString(result));
        }
        [TestMethod]
        public void Linq_Subtree_Identities_AllExisting()
        {
            var ctx = CurrentContext.Security;
            AddPermissionsForIdentityTests(ctx);
            const string expected = "101,107,201,202,203,205";

            var result = SecurityQuery.Subtree(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Select(e => e.IdentityId)
                .Distinct();

            Assert.AreEqual(expected, GetSortedIdString(result));
        }

        /* ============================================================================= PermissionQuery substitution */
        [TestMethod]
        public void Linq_PermQuery_GetRelatedIdentities()
        {
            var ctx = CurrentContext.Security;
            ctx.CreateAclEditor()
                .Allow(Id("E1"), Id("U4"), false, PermissionType.Custom04)
                .Allow(Id("E38"), Id("U5"), false, PermissionType.Custom04)
                // additions for checking local permissions.
                .Allow(Id("E1"), Id("G6"), true, PermissionType.Custom04)
                .Allow(Id("E38"), Id("G7"), true, PermissionType.Custom04)
                // additions for checking denied permissions.
                .Deny(Id("E1"), Id("U6"), false, PermissionType.Custom01)
                .Deny(Id("E1"), Id("U7"), false, PermissionType.Custom02)
                .Apply();
            ctx.CreateAclEditor()
                .BreakInheritance(Id("E4"))
                .Apply();
            ctx.CreateAclEditor()
                .ClearPermission(Id("E4"), Id("U4"), false, PermissionType.Custom04)
                .Apply();

            const string expected1 = "101,107,201,202,205";

            var pqResult1 = ctx.GetRelatedIdentities(Id("E32"), PermissionLevel.Allowed);
            Assert.AreEqual(expected1, GetSortedIdString(pqResult1));

            var result1 = PermissionQueryWithLinq_GetRelatedIdentities(ctx, Id("E32"), PermissionLevel.Allowed);
            Assert.AreEqual(expected1, GetSortedIdString(result1));

            const string expected2 = "203,206,207";

            var pqResult2 = ctx.GetRelatedIdentities(Id("E32"), PermissionLevel.Denied);
            Assert.AreEqual(expected2, GetSortedIdString(pqResult2));

            var result2 = PermissionQueryWithLinq_GetRelatedIdentities(ctx, Id("E32"), PermissionLevel.Denied);
            Assert.AreEqual(expected2, GetSortedIdString(result2));

            const string expected3 = "101,107,201,202,203,205,206,207";

            var pqResult3 = ctx.GetRelatedIdentities(Id("E32"), PermissionLevel.AllowedOrDenied);
            Assert.AreEqual(expected3, GetSortedIdString(pqResult3));

            var result3 = PermissionQueryWithLinq_GetRelatedIdentities(ctx, Id("E32"), PermissionLevel.AllowedOrDenied);
            Assert.AreEqual(expected3, GetSortedIdString(result3));
        }
        private IEnumerable<int> PermissionQueryWithLinq_GetRelatedIdentities(SecurityContext ctx, int entityId, PermissionLevel level)
        {
            bool IsActive(AceInfo entry)
            {
                switch(level)
                {
                    case PermissionLevel.Allowed:
                        return entry.AllowBits != 0ul;
                    case PermissionLevel.Denied:
                        return entry.DenyBits != 0ul;
                    case PermissionLevel.AllowedOrDenied:
                        return true;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(level), level, null);
                }
            }

            return SecurityQuery.ParentChain(ctx).GetEntities(entityId, BreakOptions.StopAtParentBreak)
                .Where(e => e.Acl != null)       // relevant entities
                .SelectMany(e => e.Acl.Entries)  // join
                .Where(e => !e.LocalOnly)        // local only entry is not affected on the parent chain
                .Where(IsActive)                 // filter by level
                .Select(e => e.IdentityId)
                .Distinct()
                .Union(SecurityQuery.Subtree(ctx).GetEntities(entityId) // do not stop at breaks
                    .Where(e => e.Acl != null)      // relevant entities
                    .SelectMany(e => e.Acl.Entries) // join
                    .Where(IsActive)                // filter by level
                    .Select(e => e.IdentityId))
                .Distinct();
        }

        /* ============================================================================= Tools */
        private void AddPermissionsForIdentityTests(TestSecurityContext ctx)
        {
            ctx.CreateAclEditor()
                // additions for easy checking of differences between parent-chain and the subtree
                .Allow(Id("E1"), Id("U4"), false, PermissionType.Custom04)
                .Allow(Id("E38"), Id("U5"), false, PermissionType.Custom04)
                // additions for validating local permissions.
                .Allow(Id("E1"), Id("G6"), true, PermissionType.Custom04)
                .Allow(Id("E38"), Id("G7"), true, PermissionType.Custom04)
                .Apply();
        }

        private int[] GetSortedIds(IEnumerable<SecurityEntity> entities)
        {
            return entities.Select(e => e.Id).OrderBy(i => i).ToArray();
        }
        private string GetSortedIdString(IEnumerable<SecurityEntity> entities)
        {
            return string.Join(",", GetSortedIds(entities).Select(i => i.ToString()).ToArray());
        }
        private string GetSortedIdString(IEnumerable<int> ids)
        {
            return string.Join(",", ids.OrderBy(i => i).Select(i => i.ToString()).ToArray());
        }
        private string GetIdString(IEnumerable<int> ids)
        {
            return string.Join(",", ids.Select(i => i.ToString()).ToArray());
        }

        #region Helper methods
        private Dictionary<int, TestEntity> _repository = new Dictionary<int, TestEntity>();

        private int _rootEntityId = 1;

        private void CreatePlayground()
        {
            TestEntity e;
            var u1 = TestUser.User1;

            CreateEntity("E1", null, u1);
            {
                CreateEntity("E2", "E1", u1); // +U1:____+, +U2:____+, +U3:____+, +G1:____+
                {
                    CreateEntity("E5", "E2", u1); // +U3___+, +G2:_+__
                    {
                        CreateEntity("E14", "E5", u1);
                        {
                            CreateEntity("E50", "E14", u1);
                            {
                                CreateEntity("E51", "E50", u1);
                                {
                                    CreateEntity("E52", "E51", u1);
                                }
                                CreateEntity("E53", "E50", u1);
                            }
                        }
                        CreateEntity("E15", "E5", u1); // +U1:__+_, +G2:__+_
                    }
                    CreateEntity("E6", "E2", u1);
                    {
                        CreateEntity("E16", "E6", u1); // +U2:__+_
                        CreateEntity("E17", "E6", u1);
                    }
                    CreateEntity("E7", "E2", u1);
                    {
                        CreateEntity("E18", "E7", u1);
                        CreateEntity("E19", "E7", u1);
                    }
                }
                CreateEntity("E3", "E1", u1);
                {
                    CreateEntity("E8", "E3", u1);
                    {
                        CreateEntity("E20", "E8", u1); // +U1:_+__
                        CreateEntity("E21", "E8", u1);
                        {
                            CreateEntity("E22", "E21", u1); // BREAK
                            CreateEntity("E23", "E21", u1);
                            CreateEntity("E24", "E21", u1);
                            CreateEntity("E25", "E21", u1); // +U2:___+
                            CreateEntity("E26", "E21", u1);
                            CreateEntity("E27", "E21", u1);
                            CreateEntity("E28", "E21", u1); // +U1:___+, +G1:__+_
                            CreateEntity("E29", "E21", u1);
                        }
                    }
                    CreateEntity("E9", "E3", u1);
                    CreateEntity("E10", "E3", u1); // +G2:__+_
                }
                CreateEntity("E4", "E1", u1); // +U3:___-, +G1:__+_
                {
                    CreateEntity("E11", "E4", u1); // +G2:__+_
                    CreateEntity("E12", "E4", u1); // +U1:_+__
                    {
                        CreateEntity("E30", "E12", u1);
                        {
                            CreateEntity("E31", "E30", u1);
                            {
                                CreateEntity("E33", "E31", u1);
                                CreateEntity("E34", "E31", u1); // BREAK +U1:_+__, +U2:___+, +U3:___-, +G1:__+_
                                {
                                    CreateEntity("E40", "E34", u1);
                                    CreateEntity("E43", "E34", u1);
                                    {
                                        CreateEntity("E44", "E43", u1);
                                        CreateEntity("E45", "E43", u1);
                                        CreateEntity("E46", "E43", u1);
                                        CreateEntity("E47", "E43", u1);
                                        CreateEntity("E48", "E43", u1);
                                        CreateEntity("E49", "E43", u1);
                                    }
                                }
                            }
                            CreateEntity("E32", "E30", u1); // +U1:___+
                            {
                                CreateEntity("E35", "E32", u1); // BREAK +U2:___+, +U3:___-, +G1:__+_
                                {
                                    CreateEntity("E41", "E35", u1); // BREAK
                                    {
                                        CreateEntity("E42", "E41", u1);
                                    }
                                }
                                CreateEntity("E36", "E32", u1); // BREAK +U3:___-, +G1:__+_
                                {
                                    CreateEntity("E37", "E36", u1); // BREAK +U3:___-, +G1:__+_
                                    {
                                        CreateEntity("E38", "E37", u1);
                                        CreateEntity("E39", "E37", u1);
                                    }
                                }
                            }
                        }
                    }
                    CreateEntity("E13", "E4", u1);
                }
            }

            var ctx = CurrentContext.Security;

            ctx.AddUsersToSecurityGroup(Id("G13"), new[] { Id("U13") });
            ctx.AddUsersToSecurityGroup(Id("G12"), new[] { Id("U12") });
            ctx.AddUsersToSecurityGroup(Id("G11"), new[] { Id("U11") });
            ctx.AddUsersToSecurityGroup(Id("G10"), new[] { Id("U10") });
            ctx.AddGroupToSecurityGroups(Id("G11"), new[] { Id("G10") });
            ctx.AddGroupToSecurityGroups(Id("G13"), new[] { Id("G11") });
            ctx.AddGroupToSecurityGroups(Id("G13"), new[] { Id("G12") });

            ctx.CreateAclEditor()
                .Allow(Id("E2"), Id("U1"), false, PermissionType.Custom01)
                .Allow(Id("E2"), Id("U2"), false, PermissionType.Custom01)
                .Allow(Id("E2"), Id("U3"), false, PermissionType.Custom01)
                .Allow(Id("E2"), Id("G1"), false, PermissionType.Custom01)

                .Deny(Id("E4"), Id("U3"), false, PermissionType.Custom01)
                .Allow(Id("E4"), Id("G1"), false, PermissionType.Custom02)

                .Allow(Id("E5"), Id("U3"), false, PermissionType.Custom01)
                .Allow(Id("E5"), Id("G2"), false, PermissionType.Custom03)

                .Allow(Id("E10"), Id("G2"), false, PermissionType.Custom02)
                .Allow(Id("E11"), Id("G2"), false, PermissionType.Custom02)
                .Allow(Id("E12"), Id("U1"), false, PermissionType.Custom03)

                .Allow(Id("E15"), Id("U1"), false, PermissionType.Custom02)
                .Allow(Id("E15"), Id("G2"), false, PermissionType.Custom02)
                .Allow(Id("E16"), Id("U2"), false, PermissionType.Custom02)
                .Allow(Id("E20"), Id("U1"), false, PermissionType.Custom03)

                .Allow(Id("E25"), Id("U2"), false, PermissionType.Custom01)

                .Allow(Id("E28"), Id("U1"), false, PermissionType.Custom01)
                .Allow(Id("E28"), Id("G1"), false, PermissionType.Custom02)

                .Allow(Id("E32"), Id("U1"), false, PermissionType.Custom01)

                .Apply();

            ctx.CreateAclEditor()
                .BreakInheritance(Id("E22"))

                .BreakInheritance(Id("E34"))
                .Allow(Id("E34"), Id("U2"), false, PermissionType.Custom01)
                .BreakInheritance(Id("E35"))
                .Allow(Id("E35"), Id("U2"), false, PermissionType.Custom01)
                .ClearPermission(Id("E35"), Id("U1"), false, PermissionType.Custom01)

                .BreakInheritance(Id("E36"))
                .ClearPermission(Id("E36"), Id("U1"), false, PermissionType.Custom01)


                .Apply();

            ctx.CreateAclEditor()
                .BreakInheritance(Id("E37"))

                // E41 and her subtree (E41, E42) is disabled for everyone except the system user
                .BreakInheritance(Id("E41"), false)

                .Apply();

        }

        private void CreateEntity(string name, string parentName, TestUser owner)
        {
            var entity = new TestEntity
            {
                Id = Id(name),
                Name = name,
                OwnerId = owner == null ? default(int) : owner.Id,
                Parent = parentName == null ? null : _repository[Id(parentName)],
            };
            _repository.Add(entity.Id, entity);
            CurrentContext.Security.CreateSecurityEntity(entity);
        }

        private int Id(string name)
        {
            return Tools.GetId(name);
        }
        #endregion

    }
}
