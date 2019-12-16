using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
        public void Linq_Root_Entries_AllExisting()
        {
            var ctx = CurrentContext.Security;

            var resultWithFilter = SecurityQuery.All(ctx).GetEntities(_rootEntityId)
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries);

            // ACTION
            var result = SecurityQuery.All(ctx).GetEntries(_rootEntityId);

            // ASSERT
            var expected = string.Join(" | ", resultWithFilter.Select(x => x.ToString()).OrderBy(x => x));
            var actual = string.Join(" | ", result.Select(x => x.ToString()).OrderBy(x => x));
            Assert.AreEqual(expected, actual);
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
                .BreakInheritance(Id("E4"), new[] { EntryType.Normal })
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
                .BreakInheritance(Id("E4"), new[] { EntryType.Normal })
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

        [TestMethod]
        public void Linq_All_IdentitiesByCategory()
        {
            var ctx = CurrentContext.Security;
            AddPermissionsForCategorySelectionTests(ctx);

            const string expectedAll = "101,106,107,108,109,201,202,203,204,205,206,207";
            const string expectedNormal = "101,106,107,201,202,203,204,205";
            const string expectedSharing = "108,109,206,207";

            var resultAll = SecurityQuery.All(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Select(e => e.IdentityId)
                .Distinct();

            var resultNormal = SecurityQuery.All(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => e.EntryType == EntryType.Normal)
                .Select(e => e.IdentityId)
                .Distinct();

            var resultSharing = SecurityQuery.All(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => e.EntryType == EntryType.Sharing)
                .Select(e => e.IdentityId)
                .Distinct();

            Assert.AreEqual(expectedAll, GetSortedIdString(resultAll));
            Assert.AreEqual(expectedNormal, GetSortedIdString(resultNormal));
            Assert.AreEqual(expectedSharing, GetSortedIdString(resultSharing));
        }
        [TestMethod]
        public void Linq_Parent_IdentitiesByCategory()
        {
            var ctx = CurrentContext.Security;
            AddPermissionsForCategorySelectionTests(ctx);

            const string expectedAll = "101,106,108,201,203,204,206";
            const string expectedNormal = "101,106,201,203,204";
            const string expectedSharing = "108,206";

            var resultAll = SecurityQuery.ParentChain(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Select(e => e.IdentityId)
                .Distinct();

            var resultNormal = SecurityQuery.ParentChain(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => e.EntryType == EntryType.Normal)
                .Select(e => e.IdentityId)
                .Distinct();

            var resultSharing = SecurityQuery.ParentChain(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => e.EntryType == EntryType.Sharing)
                .Select(e => e.IdentityId)
                .Distinct();

            Assert.AreEqual(expectedAll, GetSortedIdString(resultAll));
            Assert.AreEqual(expectedNormal, GetSortedIdString(resultNormal));
            Assert.AreEqual(expectedSharing, GetSortedIdString(resultSharing));
        }
        [TestMethod]
        public void Linq_Subtree_IdentitiesByCategory()
        {
            var ctx = CurrentContext.Security;
            AddPermissionsForCategorySelectionTests(ctx);

            const string expectedAll = "101,107,109,201,202,203,205,207";
            const string expectedNormal = "101,107,201,202,203,205";
            const string expectedSharing = "109,207";

            var resultAll = SecurityQuery.Subtree(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Select(e => e.IdentityId)
                .Distinct();

            var resultNormal = SecurityQuery.Subtree(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => e.EntryType == EntryType.Normal)
                .Select(e => e.IdentityId)
                .Distinct();

            var resultSharing = SecurityQuery.Subtree(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => e.EntryType == EntryType.Sharing)
                .Select(e => e.IdentityId)
                .Distinct();

            Assert.AreEqual(expectedAll, GetSortedIdString(resultAll));
            Assert.AreEqual(expectedNormal, GetSortedIdString(resultNormal));
            Assert.AreEqual(expectedSharing, GetSortedIdString(resultSharing));
        }

        [TestMethod]
        public void Linq_All_Identities_ByPermission()
        {
            var ctx = CurrentContext.Security;
            AddPermissionsForIdentityByPermissionTests(ctx);

            const string expected1 = "101,103,104,106,201,203,204,206";
            const string expected2 = "102,103,105,106,202,203,205,206";
            const string expected3 = "103,106,203,206";
            const string expected4 = "101,102,103,104,105,106,201,202,203,204,205,206";

            var mask1 = PermissionType.Custom11.Mask;
            var mask2 = PermissionType.Custom12.Mask;
            var mask3 = mask1 | mask2;

            var result1 = SecurityQuery.All(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask1) == mask1)
                .Select(e => e.IdentityId)
                .Distinct();

            var result2 = SecurityQuery.All(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask2) == mask2)
                .Select(e => e.IdentityId)
                .Distinct();

            // all bits
            var result3 = SecurityQuery.All(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask3) == mask3)
                .Select(e => e.IdentityId)
                .Distinct();

            // any bit
            var result4 = SecurityQuery.All(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask3) != 0)
                .Select(e => e.IdentityId)
                .Distinct();

            Assert.AreEqual(expected1, GetSortedIdString(result1));
            Assert.AreEqual(expected2, GetSortedIdString(result2));
            Assert.AreEqual(expected3, GetSortedIdString(result3));
            Assert.AreEqual(expected4, GetSortedIdString(result4));
        }
        [TestMethod]
        public void Linq_Parent_Identities_ByPermission()
        {
            var ctx = CurrentContext.Security;
            AddPermissionsForIdentityByPermissionTests(ctx);

            const string expected1 = "101,103,201,203";
            const string expected2 = "102,103,202,203";
            const string expected3 = "103,203";
            const string expected4 = "101,102,103,201,202,203";

            var mask1 = PermissionType.Custom11.Mask;
            var mask2 = PermissionType.Custom12.Mask;
            var mask3 = mask1 | mask2;

            var result1 = SecurityQuery.ParentChain(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask1) == mask1)
                .Select(e => e.IdentityId)
                .Distinct();

            var result2 = SecurityQuery.ParentChain(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask2) == mask2)
                .Select(e => e.IdentityId)
                .Distinct();

            // all bits
            var result3 = SecurityQuery.ParentChain(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask3) == mask3)
                .Select(e => e.IdentityId)
                .Distinct();

            // any bit
            var result4 = SecurityQuery.ParentChain(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask3) != 0)
                .Select(e => e.IdentityId)
                .Distinct();

            Assert.AreEqual(expected1, GetSortedIdString(result1));
            Assert.AreEqual(expected2, GetSortedIdString(result2));
            Assert.AreEqual(expected3, GetSortedIdString(result3));
            Assert.AreEqual(expected4, GetSortedIdString(result4));
        }
        [TestMethod]
        public void Linq_Subtree_Identities_ByPermission()
        {
            var ctx = CurrentContext.Security;
            AddPermissionsForIdentityByPermissionTests(ctx);

            const string expected1 = "104,106,204,206";
            const string expected2 = "105,106,205,206";
            const string expected3 = "106,206";
            const string expected4 = "104,105,106,204,205,206";

            var mask1 = PermissionType.Custom11.Mask;
            var mask2 = PermissionType.Custom12.Mask;
            var mask3 = mask1 | mask2;

            var result1 = SecurityQuery.Subtree(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask1) == mask1)
                .Select(e => e.IdentityId)
                .Distinct();

            var result2 = SecurityQuery.Subtree(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask2) == mask2)
                .Select(e => e.IdentityId)
                .Distinct();

            // all bits
            var result3 = SecurityQuery.Subtree(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask3) == mask3)
                .Select(e => e.IdentityId)
                .Distinct();

            // any bit
            var result4 = SecurityQuery.Subtree(ctx).GetEntities(Id("E32"))
                .Where(e => e.Acl != null)
                .SelectMany(e => e.Acl.Entries)
                .Where(e => (e.AllowBits & mask3) != 0)
                .Select(e => e.IdentityId)
                .Distinct();

            Assert.AreEqual(expected1, GetSortedIdString(result1));
            Assert.AreEqual(expected2, GetSortedIdString(result2));
            Assert.AreEqual(expected3, GetSortedIdString(result3));
            Assert.AreEqual(expected4, GetSortedIdString(result4));
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
                .BreakInheritance(Id("E4"), new[] { EntryType.Normal })
                .Apply();
            ctx.CreateAclEditor()
                .ClearPermission(Id("E4"), Id("U4"), false, PermissionType.Custom04)
                .Apply();

            ctx.CreateAclEditor(EntryType.Sharing)
                .Allow(Id("E12"), Id("U8"), false, PermissionType.Open)
                .Allow(Id("E41"), Id("U8"), false, PermissionType.Open)
                .Allow(Id("E38"), Id("U8"), false, PermissionType.Open)
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
                .Where(e => e.Acl != null)                              // relevant entities
                .SelectMany(e => e.Acl.Entries)                         // join
                .Where(e => !e.LocalOnly &&                             // local only entry is not affected on the parent chain
                             e.EntryType == EntryType.Normal &&         // only the normal entries are relevant
                             IsActive(e))                               // filter by level
                .Select(e => e.IdentityId)
                .Union(SecurityQuery.Subtree(ctx).GetEntities(entityId) // do not stop at breaks
                    .Where(e => e.Acl != null)                          // relevant entities
                    .SelectMany(e => e.Acl.Entries)                     // join
                    .Where(e => e.EntryType == EntryType.Normal &&      // only the normal entries are relevant
                                IsActive(e))                            // filter by level
                    .Select(e => e.IdentityId))
                .Distinct();
        }

        [TestMethod]
        public void Linq_PermQuery_GetRelatedPermissions()
        {
            var ctx = CurrentContext.Security;

            Tools.SetMembership(CurrentContext.Security, "U4:G4");
            ctx.CreateAclEditor()
                .Allow(Id("E1"), Id("G4"), false, PermissionType.Custom04)
                .Allow(Id("E42"), Id("G4"), false, PermissionType.Custom04)
                .Apply();
            ctx.CreateAclEditor(EntryType.Sharing)
                .Allow(Id("E4"), Id("U8"), false, PermissionType.Open)
                .Allow(Id("E41"), Id("U8"), false, PermissionType.Open)
                .Apply();

            // sample output: "U1:p0:1,p1:2|U2:|U3:p3:2"
            string ResultToString(Dictionary<string, Dictionary<int, int>> result)
            {
                var x = result.Select(item =>
                {
                    var sb = new StringBuilder();
                    sb.Append(item.Key);
                    foreach (var permCount in item.Value)
                        sb.Append(":").Append($"p{permCount.Key}:{permCount.Value}");
                    return sb.ToString();
                }).ToArray();
                return string.Join("|", x);
            }

            var identityNames = new[] { "U1", "U2", "U3", "U4", "U8" };

            // ---- ALLOWED
            var expectedAllowedPermCounts = "U1:p32:3:p34:4|U2:p32:2|U3|U4|U8";
            var allowedPermCountsByIdentities = ResultToString(identityNames
                .Select(identityName => new
                {
                    id = identityName,
                    permissionCounters = ctx
                        .GetRelatedPermissions(Id("E32"), PermissionLevel.Allowed, true, Id(identityName), i => true)
                        .Where(x => x.Value != 0).ToDictionary(x => x.Key.Index, x => x.Value)
                })
                .ToDictionary(x => x.id, x => x.permissionCounters));
            var allowedPermCountsByIdentitiesLinq = ResultToString(identityNames
                .Select(identityName => new
                {
                    id = identityName,
                    permissionCounters =
                        PermissionQueryWithLinq_GetRelatedPermissions(ctx, Id("E32"), Id(identityName), PermissionLevel.Allowed)
                        .Where(x => x.Value != 0).ToDictionary(x => x.Key.Index, x => x.Value)
                })
                .ToDictionary(x => x.id, x => x.permissionCounters));
            Assert.AreEqual(allowedPermCountsByIdentities, allowedPermCountsByIdentitiesLinq);
            Assert.AreEqual(expectedAllowedPermCounts, allowedPermCountsByIdentities);

            // ---- DENIED
            var expectedDeniedPermCounts = "U1|U2|U3:p32:4|U4|U8";
            var deniedPermCountsByIdentities = ResultToString(identityNames
                .Select(identityName => new
                {
                    id = identityName,
                    permissionCounters = ctx
                        .GetRelatedPermissions(Id("E32"), PermissionLevel.Denied, true, Id(identityName), i => true)
                        .Where(x => x.Value != 0).ToDictionary(x => x.Key.Index, x => x.Value)
                })
                .ToDictionary(x => x.id, x => x.permissionCounters));
            var deniedPermCountsByIdentitiesLinq = ResultToString(identityNames
                .Select(identityName => new
                {
                    id = identityName,
                    permissionCounters =
                    PermissionQueryWithLinq_GetRelatedPermissions(ctx, Id("E32"), Id(identityName), PermissionLevel.Denied)
                        .Where(x => x.Value != 0).ToDictionary(x => x.Key.Index, x => x.Value)
                })
                .ToDictionary(x => x.id, x => x.permissionCounters));
            Assert.AreEqual(deniedPermCountsByIdentities, deniedPermCountsByIdentitiesLinq);
            Assert.AreEqual(expectedDeniedPermCounts, deniedPermCountsByIdentities);

            // ALLOWED OR DENIED
            var expectedAllPermCounts = "U1:p32:3:p34:4|U2:p32:2|U3:p32:4|U4|U8";
            var allPermCountsByIdentities = ResultToString(identityNames
                .Select(identityName => new
                {
                    id = identityName,
                    permissionCounters = ctx
                        .GetRelatedPermissions(Id("E32"), PermissionLevel.AllowedOrDenied, true, Id(identityName), i => true)
                        .Where(x => x.Value != 0).ToDictionary(x => x.Key.Index, x => x.Value)
                })
                .ToDictionary(x => x.id, x => x.permissionCounters));
            var allPermCountsByIdentitiesLinq = ResultToString(identityNames
                .Select(identityName => new
                {
                    id = identityName,
                    permissionCounters =
                    PermissionQueryWithLinq_GetRelatedPermissions(ctx, Id("E32"), Id(identityName), PermissionLevel.AllowedOrDenied)
                        .Where(x => x.Value != 0).ToDictionary(x => x.Key.Index, x => x.Value)
                })
                .ToDictionary(x => x.id, x => x.permissionCounters));
            Assert.AreEqual(allPermCountsByIdentities, allPermCountsByIdentitiesLinq);
            Assert.AreEqual(expectedAllPermCounts, allPermCountsByIdentities);
        }
        private Dictionary<PermissionTypeBase, int> PermissionQueryWithLinq_GetRelatedPermissions(
            TestSecurityContext ctx, int entityId, int identityId, PermissionLevel level)
        {
            var counters = new int[PermissionTypeBase.PermissionCount];
            var permissionTypes = PermissionTypeBase.GetPermissionTypes();
            void CountBits(ulong bits)
            {
                var mask = 1uL;
                var b = bits;
                foreach (var pt in permissionTypes)
                {
                    if ((b & mask) > 0)
                        counters[pt.Index]++;
                    mask = mask << 1;
                }
            }

            var identities = new[] { identityId };
            foreach (var change in SecurityQuery.Subtree(ctx)
                .GetPermissionChanges(entityId, identities, BreakOptions.StopAtParentBreak)
                .Where(x => x.EntryType == EntryType.Normal))
            {
                switch (level)
                {
                    case PermissionLevel.Allowed:
                        CountBits(change.ChangedBits.AllowBits);
                        break;
                    case PermissionLevel.Denied:
                        CountBits(change.ChangedBits.DenyBits);
                        break;
                    case PermissionLevel.AllowedOrDenied:
                        CountBits(change.ChangedBits.AllowBits);
                        CountBits(change.ChangedBits.DenyBits);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(level), level, null);
                }
            }

            var result = new Dictionary<PermissionTypeBase, int>();
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                result.Add(PermissionTypeBase.GetPermissionTypeByIndex(i), counters[i]);

            return result;
        }
        private Dictionary<PermissionTypeBase, int> PermissionQueryWithLinq_GetRelatedPermissions_OLD(
            TestSecurityContext ctx, int entityId, int identityId, PermissionLevel level)
        {
            var counters = new int[PermissionTypeBase.PermissionCount];
            var permissionTypes = PermissionTypeBase.GetPermissionTypes();
            void CountBits(ulong bits)
            {
                var mask = 1uL;
                var b = bits;
                foreach (var pt in permissionTypes)
                {
                    if ((b & mask) > 0)
                        counters[pt.Index]++;
                    mask = mask << 1;
                }
            }

            //var identities = new TestSecurityContext(new TestUser { Id = identityId }).GetGroups();
            //identities.Add(identityId);
            var identities = new[] {identityId};

            var aces = SecurityQuery.ParentChain(ctx).GetEntities(entityId, BreakOptions.StopAtParentBreak)
                .Where(e => e.Acl != null)                              // relevant entities
                .SelectMany(e => e.Acl.Entries)                         // join
                .Where(e => identities.Contains(e.IdentityId) &&        // identity filter
                            !e.LocalOnly &&                             // local only entry is not affected on the parent chain
                            e.EntryType == EntryType.Normal)            // only the normal entries are relevant
                .Union(SecurityQuery.Subtree(ctx).GetEntities(entityId) // do not stop at breaks
                    .Where(e => e.Acl != null)                          // relevant entities
                    .SelectMany(e => e.Acl.Entries)                     // join
                    .Where(e => identities.Contains(e.IdentityId) &&    // identity filter
                                e.EntryType == EntryType.Normal)        // only the normal entries are relevant
                );

            foreach (var ace in aces)
            {
                switch (level)
                {
                    case PermissionLevel.Allowed:
                        CountBits(ace.AllowBits);
                        break;
                    case PermissionLevel.Denied:
                        CountBits(ace.DenyBits);
                        break;
                    case PermissionLevel.AllowedOrDenied:
                        CountBits(ace.AllowBits);
                        CountBits(ace.DenyBits);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(level), level, null);
                }
            }

            var result = new Dictionary<PermissionTypeBase, int>();
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                result.Add(PermissionTypeBase.GetPermissionTypeByIndex(i), counters[i]);

            return result;
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
        private void AddPermissionsForCategorySelectionTests(TestSecurityContext ctx)
        {
            ctx.CreateAclEditor()
                // additions for easy checking of differences between parent-chain and the subtree
                .Allow(Id("E1"), Id("U4"), false, PermissionType.Custom04)
                .Allow(Id("E38"), Id("U5"), false, PermissionType.Custom04)
                // additions for validating local permissions.
                .Allow(Id("E1"), Id("G6"), false, PermissionType.Custom04)
                .Allow(Id("E38"), Id("G7"), false, PermissionType.Custom04)
                .Apply();

            // add some sharing related entries
            ctx.CreateAclEditor(EntryType.Sharing)
                .Allow(Id("E4"), Id("U6"), false, PermissionType.Custom04)
                .Allow(Id("E39"), Id("U7"), false, PermissionType.Custom04)
                .Allow(Id("E4"), Id("G8"), false, PermissionType.Custom04)
                .Allow(Id("E39"), Id("G9"), false, PermissionType.Custom04)
                .Apply();
        }
        private void AddPermissionsForIdentityByPermissionTests(TestSecurityContext ctx)
        {
            var p1 = PermissionType.Custom11;
            var p2 = PermissionType.Custom12;
            ctx.CreateAclEditor()
                .Allow(Id("E1"), Id("U1"), false, p1)
                .Allow(Id("E1"), Id("U2"), false, p2)
                .Allow(Id("E1"), Id("U3"), false, p1, p2)
                .Allow(Id("E1"), Id("G1"), false, p1)
                .Allow(Id("E1"), Id("G2"), false, p2)
                .Allow(Id("E1"), Id("G3"), false, p1, p2)
                .Allow(Id("E38"), Id("U4"), false, p1)
                .Allow(Id("E38"), Id("U5"), false, p2)
                .Allow(Id("E38"), Id("U6"), false, p1, p2)
                .Allow(Id("E38"), Id("G4"), false, p1)
                .Allow(Id("E38"), Id("G5"), false, p2)
                .Allow(Id("E38"), Id("G6"), false, p1, p2)
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
        private readonly Dictionary<int, TestEntity> _repository = new Dictionary<int, TestEntity>();

        private int _rootEntityId = 1;

        private void CreatePlayground()
        {
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
                .BreakInheritance(Id("E22"), new[] { EntryType.Normal })

                .BreakInheritance(Id("E34"), new[] { EntryType.Normal })
                .Allow(Id("E34"), Id("U2"), false, PermissionType.Custom01)
                .BreakInheritance(Id("E35"), new[] { EntryType.Normal })
                .Allow(Id("E35"), Id("U2"), false, PermissionType.Custom01)
                .ClearPermission(Id("E35"), Id("U1"), false, PermissionType.Custom01)

                .BreakInheritance(Id("E36"), new[] { EntryType.Normal })
                .ClearPermission(Id("E36"), Id("U1"), false, PermissionType.Custom01)


                .Apply();

            ctx.CreateAclEditor()
                .BreakInheritance(Id("E37"), new[] { EntryType.Normal })

                // E41 and her subtree (E41, E42) is disabled for everyone except the system user
                .BreakInheritance(Id("E41"), new EntryType[0])

                .Apply();

        }

        private void CreateEntity(string name, string parentName, TestUser owner)
        {
            var entity = new TestEntity
            {
                Id = Id(name),
                Name = name,
                OwnerId = owner == null ? default : owner.Id,
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
