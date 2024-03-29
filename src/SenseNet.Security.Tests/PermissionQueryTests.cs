﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SenseNet.Diagnostics;

// ReSharper disable JoinDeclarationAndInitializer
// ReSharper disable UnusedMethodReturnValue.Local

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class PermissionQueryTests : TestBase
    {
        private Context CurrentContext { get; set; }

        public TestContext TestContext { get; set; }

        private SnTrace.Operation _snTraceOperation;
        [TestInitialize]
        public void StartTest()
        {
            _StartTest(TestContext);

            CurrentContext = GetEmptyContext(TestUser.User1);
            CreatePlaygroundAsync(CancellationToken.None).GetAwaiter().GetResult();
        }

        [TestCleanup]
        public void FinishTest()
        {
            try
            {
                CheckIntegrity(TestContext.TestName, CurrentContext.Security);
            }
            finally
            {
                _FinishTest(TestContext);
            }
        }

        //---------------------------------------------------------------

        [TestMethod]
        public void PermissionQuery_GetRelatedIdentities()
        {
            var result = CurrentContext.Security.GetRelatedIdentities(Id("E3"), PermissionLevel.AllowedOrDenied);
            var actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual($"{Id("G1")}, {Id("G2")}, {Id("U1")}, {Id("U2")}, {Id("U3")}", actual);

            result = CurrentContext.Security.GetRelatedIdentities(Id("E4"), PermissionLevel.AllowedOrDenied);
            actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual($"{Id("G1")}, {Id("G2")}, {Id("U1")}, {Id("U3")}", actual);

            result = CurrentContext.Security.GetRelatedIdentities(Id("E22"), PermissionLevel.AllowedOrDenied);
            actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual($"{Id("G1")}, {Id("U1")}, {Id("U2")}, {Id("U3")}", actual);
        }

        [TestMethod]
        public void PermissionQuery_GetRelatedEntities_AllowedOrDenied()
        {
            var perms = new[] { PermissionType.Custom01 };
            var result = CurrentContext.Security.GetRelatedEntities(Id("E3"), PermissionLevel.AllowedOrDenied, true, Id("U1"), perms);
            var actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual($"{Id("E22")}, {Id("E28")}", actual);

            perms = new[] { PermissionType.Custom02 };
            result = CurrentContext.Security.GetRelatedEntities(Id("E3"), PermissionLevel.AllowedOrDenied, true, Id("U1"), perms);
            actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual(Id("E15").ToString(), actual);

            perms = new[] { PermissionType.Custom03 };
            result = CurrentContext.Security.GetRelatedEntities(Id("E3"), PermissionLevel.AllowedOrDenied, true, Id("U1"), perms);
            actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual($"{Id("E12")}, {Id("E20")}", actual);

            perms = new[] { PermissionType.Custom01, PermissionType.Custom02, PermissionType.Custom03 };
            result = CurrentContext.Security.GetRelatedEntities(Id("E3"), PermissionLevel.AllowedOrDenied, true, Id("U1"), perms);
            actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual($"{Id("E12")}, {Id("E15")}, {Id("E20")}, {Id("E22")}, {Id("E28")}", actual);

            perms = new[] { PermissionType.Custom01, PermissionType.Custom02, PermissionType.Custom03 };
            result = CurrentContext.Security.GetRelatedEntities(Id("E3"), PermissionLevel.AllowedOrDenied, true, Id("U3"), perms);
            actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual($"{Id("E4")}, {Id("E5")}, {Id("E22")}", actual);
        }

        [TestMethod]
        public void PermissionQuery_GetRelatedEntities_Allowed()
        {
            var perms = new[] { PermissionType.Custom01 };
            var result = CurrentContext.Security.GetRelatedEntities(Id("E3"), PermissionLevel.Allowed, true, Id("U3"), perms);
            var actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual($"{Id("E5")}, {Id("E22")}", actual);
        }

        [TestMethod]
        public void PermissionQuery_GetRelatedEntities_Denied()
        {
            var perms = new[] { PermissionType.Custom01 };
            var result = CurrentContext.Security.GetRelatedEntities(Id("E3"), PermissionLevel.Denied, true, Id("U3"), perms);
            var actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual(Id("E4").ToString(), actual);
        }

        [TestMethod]
        public void PermissionQuery_GetRelatedEntities_AboveBrokenNoExplicit()
        {
            var perms = new[] { PermissionType.Custom01 };
            var result = CurrentContext.Security.GetRelatedEntities(Id("E33"), PermissionLevel.AllowedOrDenied, true, Id("U1"), perms);
            var actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual($"{Id("E34")}, {Id("E35")}, {Id("E36")}, {Id("E37")}", actual);

            result = CurrentContext.Security.GetRelatedEntities(Id("E33"), PermissionLevel.AllowedOrDenied, true, Id("U2"), perms);
            actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual($"{Id("E34")}, {Id("E35")}", actual);
        }
        
        [TestMethod]
        public void PermissionQuery_GetRelatedItemsOneLevel()
        {
            IEnumerable<int> result;
            string actual;

            var permissionTypes = new[] { PermissionType.Custom01, PermissionType.Custom02, PermissionType.Custom03 };

            result = CurrentContext.Security.GetRelatedEntitiesOneLevel(Id("E2"), PermissionLevel.AllowedOrDenied, Id("G1"), permissionTypes);
            actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual(Id("E3").ToString(), actual);

            result = CurrentContext.Security.GetRelatedEntitiesOneLevel(Id("E3"), PermissionLevel.AllowedOrDenied, Id("G2"), permissionTypes);
            actual = string.Join(", ", result.OrderBy(x => x));
            Assert.AreEqual(Id("E15").ToString(), actual);

            result = CurrentContext.Security.GetRelatedEntitiesOneLevel(Id("E4"), PermissionLevel.AllowedOrDenied, Id("G2"), permissionTypes);
            actual = string.Join(", ", result.OrderBy(x => x)); 
            Assert.AreEqual($"{Id("E5")}, {Id("E11")}", actual);

            result = CurrentContext.Security.GetRelatedEntitiesOneLevel(Id("E3"), PermissionLevel.Denied, Id("U3"), permissionTypes);
            actual = string.Join(", ", result.OrderBy(x => x)); 
            Assert.AreEqual(Id("E4").ToString(), actual);

            result = CurrentContext.Security.GetRelatedEntitiesOneLevel(Id("E3"), PermissionLevel.Denied, Id("G1"), permissionTypes);
            actual = string.Join(", ", result.OrderBy(x => x)); 
            Assert.AreEqual("", actual);

            result = CurrentContext.Security.GetRelatedEntitiesOneLevel(Id("E33"), PermissionLevel.Allowed, Id("U2"), permissionTypes);
            actual = string.Join(", ", result.OrderBy(x => x)); 
            Assert.AreEqual($"{Id("E34")}, {Id("E35")}", actual);
        }

        //---------------------------------------------------------------

        private readonly Dictionary<string, PermissionType> _permissions = new Dictionary<string, PermissionType>
        {
            {"P1", PermissionType.Custom01},
            {"P2", PermissionType.Custom02},
            {"P3", PermissionType.Custom03},
            {"P4", PermissionType.Custom04},
            {"P5", PermissionType.Custom05},
            {"P6", PermissionType.Custom06}
        };

        [TestMethod]
        public void PermissionQuery_GetAllowedUsers_Prerequisites()
        {
            var u10 = new TestUser { Id = Id("U10"), Name = "U10" };
            var u11 = new TestUser { Id = Id("U11"), Name = "U11" };
            var u12 = new TestUser { Id = Id("U12"), Name = "U12" };
            var u13 = new TestUser { Id = Id("U13"), Name = "U13" };
            var id10 = u10.Id;
            var id11 = u11.Id;
            var id12 = u12.Id;
            var id13 = u13.Id;

            Assert.IsFalse(HasNormalPermission(id10, Id("E66"), _permissions["P1"]));
            Assert.IsFalse(HasNormalPermission(id11, Id("E66"), _permissions["P1"]));
            Assert.IsFalse(HasNormalPermission(id12, Id("E66"), _permissions["P1"]));
            Assert.IsTrue(HasNormalPermission(id13, Id("E66"), _permissions["P1"]));

            Assert.IsTrue(HasNormalPermission(id10, Id("E66"), _permissions["P2"]));
            Assert.IsTrue(HasNormalPermission(id11, Id("E66"), _permissions["P2"]));
            Assert.IsFalse(HasNormalPermission(id12, Id("E66"), _permissions["P2"]));
            Assert.IsTrue(HasNormalPermission(id13, Id("E66"), _permissions["P2"]));

            Assert.IsFalse(HasNormalPermission(id10, Id("E66"), _permissions["P3"]));
            Assert.IsFalse(HasNormalPermission(id11, Id("E66"), _permissions["P3"]));
            Assert.IsTrue(HasNormalPermission(id12, Id("E66"), _permissions["P3"]));
            Assert.IsTrue(HasNormalPermission(id13, Id("E66"), _permissions["P3"]));

            Assert.IsFalse(HasNormalPermission(id10, Id("E66"), _permissions["P4"]));
            Assert.IsFalse(HasNormalPermission(id11, Id("E66"), _permissions["P4"]));
            Assert.IsFalse(HasNormalPermission(id12, Id("E66"), _permissions["P4"]));
            Assert.IsTrue(HasNormalPermission(id13, Id("E66"), _permissions["P4"]));

            Assert.IsTrue(HasNormalPermission(id10, Id("E66"), _permissions["P5"]));
            Assert.IsFalse(HasNormalPermission(id11, Id("E66"), _permissions["P5"]));
            Assert.IsFalse(HasNormalPermission(id12, Id("E66"), _permissions["P5"]));
            Assert.IsFalse(HasNormalPermission(id13, Id("E66"), _permissions["P5"]));

            Assert.IsFalse(HasNormalPermission(id10, Id("E66"), _permissions["P6"]));
            Assert.IsFalse(HasNormalPermission(id11, Id("E66"), _permissions["P6"]));
            Assert.IsTrue(HasNormalPermission(id12, Id("E66"), _permissions["P6"]));
            Assert.IsFalse(HasNormalPermission(id13, Id("E66"), _permissions["P6"]));
        }
        private bool HasNormalPermission(int userId, int entityId, PermissionType permission)
        {
            return new SecurityContext(TestUser.User1, CurrentContext.Security.SecuritySystem)
                .Evaluator.GetPermission(userId, entityId, 0, EntryType.Normal, permission) == PermissionValue.Allowed;
        }

        [TestMethod]
        public void PermissionQuery_GetAllowedUsers()
        {
            Assert.AreEqual("U13",             GetAllowedUsers("E66", "P1"));
            Assert.AreEqual("U10, U11, U13",   GetAllowedUsers("E66", "P2"));
            Assert.AreEqual("U12, U13",        GetAllowedUsers("E66", "P3"));
            Assert.AreEqual("U13",             GetAllowedUsers("E66", "P4"));
            Assert.AreEqual("U10",             GetAllowedUsers("E66", "P5"));
            Assert.AreEqual("U12",             GetAllowedUsers("E66", "P6"));

            Assert.AreEqual("U13",             GetAllowedUsers("E66", "P1", "P2", "P3", "P4"));
            Assert.AreEqual("U10",             GetAllowedUsers("E66", "P2", "P5"));
            Assert.AreEqual("U12",             GetAllowedUsers("E66", "P3", "P6"));
        }
        private string GetAllowedUsers(string entityName, params string[] permissions)
        {
            var entityId = Id(entityName);
            var permTypes = permissions.Select(p => _permissions[p]).ToArray();
            var result = CurrentContext.Security.GetAllowedUsers(entityId, permTypes);
            return string.Join(", ", result.Select(IdToName).OrderBy(s => s));
        }

        [TestMethod]
        public void PermissionQuery_GetParentGroups_DirectOnly()
        {
            Assert.AreEqual("G10",      GetParentGroups("U10", true));
            Assert.AreEqual("G11",      GetParentGroups("U11", true));
            Assert.AreEqual("G12",      GetParentGroups("U12", true));
            Assert.AreEqual("G13",      GetParentGroups("U13", true));

            Assert.AreEqual("",         GetParentGroups("G10", true));
            Assert.AreEqual("G10",      GetParentGroups("G11", true));
            Assert.AreEqual("",         GetParentGroups("G12", true));
            Assert.AreEqual("G11, G12", GetParentGroups("G13", true));
        }
        [TestMethod]
        public void PermissionQuery_GetParentGroups_All()
        {
            Assert.AreEqual("G10",                GetParentGroups("U10", false));
            Assert.AreEqual("G10, G11",           GetParentGroups("U11", false));
            Assert.AreEqual("G12",                GetParentGroups("U12", false));
            Assert.AreEqual("G10, G11, G12, G13", GetParentGroups("U13", false));

            Assert.AreEqual("",                   GetParentGroups("G10", false));
            Assert.AreEqual("G10",                GetParentGroups("G11", false));
            Assert.AreEqual("",                   GetParentGroups("G12", false));
            Assert.AreEqual("G10, G11, G12",      GetParentGroups("G13", false));
        }
        private string GetParentGroups(string identityName, bool directOnly)
        {
            var identityId = Id(identityName);
            var result = CurrentContext.Security.GetParentGroups(identityId, directOnly);
            return string.Join(", ", result.Select(IdToName).OrderBy(s => s));
        }

        #region Helper methods
        private readonly Dictionary<int, TestEntity> _repository = new Dictionary<int, TestEntity>();

        private async Task CreatePlaygroundAsync(CancellationToken cancel)
        {
            var u1 = TestUser.User1;

            CreateEntity("E1", null, u1);
            {
                CreateEntity("E2", "E1", u1);
                {
                    CreateEntity("E3", "E2", u1);
                    {
                        CreateEntity("E4", "E3", u1);
                        {
                            CreateEntity("E5", "E4", u1);
                            {
                                CreateEntity("E6", "E5", u1);
                                CreateEntity("E7", "E5", u1);
                                CreateEntity("E8", "E5", u1);
                            }
                            CreateEntity("E9", "E4", u1);
                            {
                                CreateEntity("E10", "E9", u1);
                            }
                            CreateEntity("E11", "E4", u1);
                            {
                                CreateEntity("E12", "E11", u1);
                                CreateEntity("E13", "E11", u1);
                                CreateEntity("E14", "E11", u1);
                            }
                        }
                        CreateEntity("E15", "E3", u1);
                        {
                            CreateEntity("E16", "E15", u1);
                            CreateEntity("E17", "E15", u1);
                            {
                                CreateEntity("E18", "E17", u1);
                                CreateEntity("E19", "E17", u1);
                                CreateEntity("E20", "E17", u1);
                            }
                            CreateEntity("E21", "E15", u1);
                        }
                        CreateEntity("E22", "E3", u1);
                        {
                            CreateEntity("E23", "E22", u1);
                            {
                                CreateEntity("E24", "E23", u1);
                                CreateEntity("E25", "E23", u1);
                                CreateEntity("E26", "E23", u1);
                            }
                            CreateEntity("E27", "E22", u1);
                            CreateEntity("E28", "E22", u1);
                            {
                                CreateEntity("E29", "E28", u1);
                                CreateEntity("E30", "E28", u1);
                                CreateEntity("E31", "E28", u1);
                            }
                        }
                    }
                }
                CreateEntity("E32", "E1", u1);
                {
                    CreateEntity("E33", "E32", u1);
                    {
                        CreateEntity("E34", "E33", u1);
                        CreateEntity("E35", "E33", u1);
                        CreateEntity("E36", "E33", u1);
                        CreateEntity("E37", "E33", u1);
                    }
                }
                CreateEntity("E60", "E1", u1);
                {
                    CreateEntity("E61", "E60", u1);
                    {
                        CreateEntity("E62", "E61", u1);
                        {
                            CreateEntity("E63", "E62", u1);
                            {
                                CreateEntity("E64", "E63", u1);
                                {
                                    CreateEntity("E65", "E64", u1);
                                    {
                                        CreateEntity("E66", "E65", u1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            var ctx = CurrentContext.Security;

            await ctx.AddUsersToSecurityGroupAsync(Id("G13"), new[] {Id("U13")}, cancel).ConfigureAwait(false);
            await ctx.AddUsersToSecurityGroupAsync(Id("G12"), new[] {Id("U12")}, cancel).ConfigureAwait(false);
            await ctx.AddUsersToSecurityGroupAsync(Id("G11"), new[] {Id("U11")}, cancel).ConfigureAwait(false);
            await ctx.AddUsersToSecurityGroupAsync(Id("G10"), new[] {Id("U10")}, cancel).ConfigureAwait(false);
            await ctx.AddGroupToSecurityGroupsAsync(Id("G11"), new[] {Id("G10")}, cancel).ConfigureAwait(false);
            await ctx.AddGroupToSecurityGroupsAsync(Id("G13"), new[] {Id("G11")}, cancel).ConfigureAwait(false);
            await ctx.AddGroupToSecurityGroupsAsync(Id("G13"), new[] {Id("G12")}, cancel).ConfigureAwait(false);

            await ctx.CreateAclEditor()
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

                .BreakInheritance(Id("E22"), new[] {EntryType.Normal})
                .Allow(Id("E25"), Id("U2"), false, PermissionType.Custom01)
                .Allow(Id("E28"), Id("U1"), false, PermissionType.Custom01)
                .Allow(Id("E28"), Id("G1"), false, PermissionType.Custom02)

                .Allow(Id("E32"), Id("U1"), false, PermissionType.Custom01)
                .BreakInheritance(Id("E34"), new[] {EntryType.Normal})
                .Allow(Id("E34"), Id("U2"), false, PermissionType.Custom01)
                .BreakInheritance(Id("E35"), new[] {EntryType.Normal})
                .Allow(Id("E35"), Id("U2"), false, PermissionType.Custom01)
                .ClearPermission(Id("E35"), Id("U1"), false, PermissionType.Custom01)

                .BreakInheritance(Id("E36"), new[] {EntryType.Normal})
                .ClearPermission(Id("E36"), Id("U1"), false, PermissionType.Custom01)
                .BreakInheritance(Id("E37"), new[] {EntryType.Normal})

                //---------------------------------------
                .Allow(Id("E61"), Id("G13"), false, PermissionType.Custom01)
                .Allow(Id("E62"), Id("G10"), false, PermissionType.Custom02)
                .Allow(Id("E63"), Id("G12"), false, PermissionType.Custom03)
                .Allow(Id("E64"), Id("U13"), false, PermissionType.Custom04)
                .Allow(Id("E65"), Id("U10"), false, PermissionType.Custom05)
                .Allow(Id("E66"), Id("U12"), false, PermissionType.Custom06)

                .ApplyAsync(cancel).ConfigureAwait(false);

            var users = new[] { "U1", "U2", "U3", "U4", "U10", "U12" };
            var sharingPerms = PermissionTypeBase.GetPermissionTypes();
            var aclEd = ctx.CreateAclEditor(EntryType.Sharing);
            foreach (var user in users)
            {
                var userId = Id(user);
                aclEd
                    .Allow(Id("E2"), userId, false, sharingPerms)
                    .Allow(Id("E3"), userId, false, sharingPerms)
                    .Allow(Id("E4"), userId, false, sharingPerms)
                    .Allow(Id("E5"), userId, false, sharingPerms)
                    .Allow(Id("E6"), userId, false, sharingPerms)
                    .Allow(Id("E7"), userId, false, sharingPerms)
                    .Allow(Id("E8"), userId, false, sharingPerms)
                    .Allow(Id("E9"), userId, false, sharingPerms)
                    .Allow(Id("E10"), userId, false, sharingPerms)
                    .Allow(Id("E11"), userId, false, sharingPerms)
                    .Allow(Id("E12"), userId, false, sharingPerms)
                    .Allow(Id("E15"), userId, false, sharingPerms)
                    .Allow(Id("E16"), userId, false, sharingPerms)
                    .Allow(Id("E20"), userId, false, sharingPerms)
                    .Allow(Id("E22"), userId, false, sharingPerms)
                    .Allow(Id("E25"), userId, false, sharingPerms)
                    .Allow(Id("E28"), userId, false, sharingPerms)
                    .Allow(Id("E32"), userId, false, sharingPerms)
                    .Allow(Id("E34"), userId, false, sharingPerms)
                    .Allow(Id("E35"), userId, false, sharingPerms)
                    .Allow(Id("E36"), userId, false, sharingPerms)
                    .Allow(Id("E61"), userId, false, sharingPerms)
                    .Allow(Id("E62"), userId, false, sharingPerms)
                    .Allow(Id("E63"), userId, false, sharingPerms)
                    .Allow(Id("E64"), userId, false, sharingPerms)
                    .Allow(Id("E65"), userId, false, sharingPerms)
                    .Allow(Id("E66"), userId, false, sharingPerms);
            }
            await aclEd.ApplyAsync(cancel).ConfigureAwait(false);
        }

        private TestEntity CreateEntity(string name, string parentName, TestUser owner)
        {
            var entity = new TestEntity
            {
                Id = Id(name),
                Name = name,
                OwnerId = owner?.Id ?? default,
                Parent = parentName == null ? null : _repository[Id(parentName)]
            };
            _repository.Add(entity.Id, entity);
            CurrentContext.Security.CreateSecurityEntityAsync(entity.Id, entity.ParentId, entity.OwnerId, CancellationToken.None)
                .GetAwaiter().GetResult();
            return entity;
        }

        private static int Id(string name)
        {
            return Tools.GetId(name);
        } 
        #endregion
    }
}
