using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    public abstract partial class TestCases
    {
        [TestMethod]
        public void Sharing_GetAcl()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            SetMembership(ctx, "U1:G1");

            SetAcl("+E1| Normal|+G1:______________+"); // 0x1
            SetAcl("+E1|Sharing|+G1:___________+___"); // 0x8
            SetAcl("+E2| Normal|+G1:_____________+_"); // 0x2
            SetAcl("+E2|Sharing|+G1:__________+____"); // 0x10
            SetAcl("+E2| Normal|-G1:____________+__"); // 0x4   local
            SetAcl("+E2|Sharing|-G1:_________+_____"); // 0x20  local

            // ACTION 1 root, default filter (Normal)
            var entries = ctx.GetAcl(Id("E1")).Entries
                .OrderBy(x => x.LocalOnly).ThenBy(x => x.EntryType).ToList();
            Assert.AreEqual("Normal|+G1:_______________________________________________________________+", ReplaceIds(entries[0].ToString()));

            // ACTION 2 child, default filter (Normal)
            entries = ctx.GetAcl(Id("E2")).Entries
                .OrderBy(x => x.LocalOnly).ThenBy(x => x.EntryType).ToList();
            Assert.AreEqual("Normal|+G1:______________________________________________________________++", ReplaceIds(entries[0].ToString()));
            Assert.AreEqual("Normal|-G1:_____________________________________________________________+__", ReplaceIds(entries[1].ToString()));

            // ACTION 3 root, Normal only
            entries = ctx.GetAcl(Id("E1")).Entries
                .OrderBy(x => x.LocalOnly).ThenBy(x => x.EntryType).ToList();
            Assert.AreEqual("Normal|+G1:_______________________________________________________________+", ReplaceIds(entries[0].ToString()));

            // ACTION 4 child, Normal only
            entries = ctx.GetAcl(Id("E2")).Entries
                .OrderBy(x => x.LocalOnly).ThenBy(x => x.EntryType).ToList();
            Assert.AreEqual("Normal|+G1:______________________________________________________________++", ReplaceIds(entries[0].ToString()));
            Assert.AreEqual("Normal|-G1:_____________________________________________________________+__", ReplaceIds(entries[1].ToString()));

            // ACTION 3 root, Sharing only
            entries = ctx.GetAcl(Id("E1"), EntryType.Sharing).Entries
                .OrderBy(x => x.LocalOnly).ThenBy(x => x.EntryType).ToList();
            Assert.AreEqual("Sharing|+G1:____________________________________________________________+___", ReplaceIds(entries[0].ToString()));

            // ACTION 4 child, Sharing only
            entries = ctx.GetAcl(Id("E2"), EntryType.Sharing).Entries
                .OrderBy(x => x.LocalOnly).ThenBy(x => x.EntryType).ToList();
            Assert.AreEqual("Sharing|+G1:___________________________________________________________++___", ReplaceIds(entries[0].ToString()));
            Assert.AreEqual("Sharing|-G1:__________________________________________________________+_____", ReplaceIds(entries[1].ToString()));
        }
        [TestMethod]
        public void Sharing_GetAcl_FirstAclIsNotRelevant()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            SetMembership(ctx, "U1:G1");

            SetAcl("+E1| Normal|+G1:___________++++"); // 0x1
            SetAcl("+E2|Sharing|+G1:_______++++____"); // 0x10

            // ACTION 1: default filter (Normal)
            var entry = ctx.GetAcl(Id("E5")).Entries.First();
            Assert.AreEqual("Normal|+G1:____________________________________________________________++++", ReplaceIds(entry.ToString()));

            // ACTION 2: Normal only
            entry = ctx.GetAcl(Id("E5")).Entries.First();
            Assert.AreEqual("Normal|+G1:____________________________________________________________++++", ReplaceIds(entry.ToString()));

            // ACTION 3: Sharing only
            entry = ctx.GetAcl(Id("E5"), EntryType.Sharing).Entries.First();
            Assert.AreEqual("Sharing|+G1:________________________________________________________++++____", ReplaceIds(entry.ToString()));
        }

        [TestMethod]
        public void Sharing_Eval_CheckPermissions()
        {
            EnsureRepository();
            SetMembership(CurrentContext.Security, "U1:G1");

            // Root permission for G1. The U1 is a member for it.
            SetAcl("+E1| Normal|+G1:_+_______________+"); // See + Run
            // One level down: The sharing permits many more but only local.
            SetAcl("+E2|Sharing|-U1:___________+++++++"); // Save
            // Two level down: The sharing permits less than on parent.
            SetAcl("+E5|Sharing|+U1:_____________+++++"); // Open

            var ctx = CurrentContext.Security;

            var entityId = Id("E1"); // Root
            var see = ctx.GetPermission(entityId, PermissionType.See);
            var open = ctx.GetPermission(entityId, PermissionType.Open);
            var save = ctx.GetPermission(entityId, PermissionType.Save);
            var run = ctx.GetPermission(entityId, PermissionType.RunApplication);
            Assert.AreEqual(PermissionValue.Allowed, see);
            Assert.AreEqual(PermissionValue.Undefined, open);
            Assert.AreEqual(PermissionValue.Undefined, save);
            Assert.AreEqual(PermissionValue.Allowed, run);
            Assert.IsTrue(ctx.HasPermission(entityId, PermissionType.See, PermissionType.RunApplication));

            entityId = Id("E2"); // E1/E2
            see = ctx.GetPermission(entityId, PermissionType.See);
            open = ctx.GetPermission(entityId, PermissionType.Open);
            save = ctx.GetPermission(entityId, PermissionType.Save);
            run = ctx.GetPermission(entityId, PermissionType.RunApplication);
            Assert.AreEqual(PermissionValue.Allowed, see);
            Assert.AreEqual(PermissionValue.Allowed, open);
            Assert.AreEqual(PermissionValue.Allowed, save);
            Assert.AreEqual(PermissionValue.Allowed, run);
            Assert.IsTrue(ctx.HasPermission(entityId, PermissionType.Save, PermissionType.RunApplication));

            entityId = Id("E6"); // E1/E2/E6
            see = ctx.GetPermission(entityId, PermissionType.See);
            open = ctx.GetPermission(entityId, PermissionType.Open);
            save = ctx.GetPermission(entityId, PermissionType.Save);
            run = ctx.GetPermission(entityId, PermissionType.RunApplication);
            Assert.AreEqual(PermissionValue.Allowed, see);
            Assert.AreEqual(PermissionValue.Undefined, open);
            Assert.AreEqual(PermissionValue.Undefined, save);
            Assert.AreEqual(PermissionValue.Allowed, run);
            Assert.IsTrue(ctx.HasPermission(entityId, PermissionType.See, PermissionType.RunApplication));

            entityId = Id("E14"); // E1/E2/E5/E14
            see = ctx.GetPermission(entityId, PermissionType.See);
            open = ctx.GetPermission(entityId, PermissionType.Open);
            save = ctx.GetPermission(entityId, PermissionType.Save);
            run = ctx.GetPermission(entityId, PermissionType.RunApplication);
            Assert.AreEqual(PermissionValue.Allowed, see);
            Assert.AreEqual(PermissionValue.Allowed, open);
            Assert.AreEqual(PermissionValue.Undefined, save);
            Assert.AreEqual(PermissionValue.Allowed, run);
            Assert.IsTrue(ctx.HasPermission(entityId, PermissionType.Open, PermissionType.RunApplication));
        }
        [TestMethod]
        public void Sharing_Eval_HasPermission_OverBreak()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            SetMembership(ctx, "U1:G1");

            SetAcl("+E1|Sharing|+G1:______________+");
            SetAcl("-E2| Normal|+G1:_____________+_");

            Assert.IsFalse(ctx.HasPermission(Id("E2"), PermissionType.See));
            Assert.IsTrue(ctx.HasPermission(Id("E2"), PermissionType.Preview));
        }

        [TestMethod]
        public void Sharing_Acl_BreakOperation_Default_SharingNotCopied()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            SetMembership(ctx, "U1:G1,G2");

            SetAcl("+E1|Sharing|+G1:______________+");
            SetAcl("+E1| Normal|+G1:_____________+_");
            SetAcl("+E2| Normal|+G1:____________+__");
            SetAcl("+E3| Normal|+G2:_____________+_");

            // ACTION
            var ed = ctx.CreateAclEditor();
            ed.BreakInheritance(Id("E5"), new[] { EntryType.Normal });
            ed.BreakInheritance(Id("E8"), new[] { EntryType.Normal });
            ed.Apply();

            // ASSERT
            var entries5 = ctx.GetExplicitEntries(Id("E5")) // E1/E2/E5
                .OrderBy(x => x.EntryType).ThenBy(x => x.IdentityId).ToList();
            var entries8 = ctx.GetExplicitEntries(Id("E8")) // E1/E3/E8
                .OrderBy(x => x.EntryType).ThenBy(x => x.IdentityId).ToList();

            Assert.AreEqual(1, entries5.Count);
            Assert.AreEqual("Normal|+G1:_____________________________________________________________++_", ReplaceIds(entries5[0].ToString()));

            Assert.AreEqual(2, entries8.Count);
            Assert.AreEqual("Normal|+G1:______________________________________________________________+_", ReplaceIds(entries8[0].ToString()));
            Assert.AreEqual("Normal|+G2:______________________________________________________________+_", ReplaceIds(entries8[1].ToString()));
        }
        [TestMethod]
        public void Sharing_Acl_BreakOperation_EverythingCopied()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            SetMembership(ctx, "U1:G1,G2");

            SetAcl("+E1|Sharing|+G1:______________+");
            SetAcl("+E1| Normal|+G1:_____________+_");
            SetAcl("+E2| Normal|+G1:____________+__");
            SetAcl("+E3| Normal|+G2:_____________+_");

            // ACTION
            var ed = ctx.CreateAclEditor();
            ed.BreakInheritance(Id("E5"), new[] { EntryType.Normal, EntryType.Sharing });
            ed.BreakInheritance(Id("E8"), new[] { EntryType.Normal, EntryType.Sharing });
            ed.Apply();

            // ASSERT
            var entries5 = ctx.GetExplicitEntries(Id("E5")) // E1/E2/E5
                .OrderBy(x => x.EntryType).ThenBy(x => x.IdentityId).ToList();
            var entries8 = ctx.GetExplicitEntries(Id("E8")) // E1/E3/E8
                .OrderBy(x => x.EntryType).ThenBy(x => x.IdentityId).ToList();

            Assert.AreEqual(2, entries5.Count);
            Assert.AreEqual( "Normal|+G1:_____________________________________________________________++_", ReplaceIds(entries5[0].ToString()));
            Assert.AreEqual("Sharing|+G1:_______________________________________________________________+", ReplaceIds(entries5[1].ToString()));

            Assert.AreEqual(3, entries8.Count);
            Assert.AreEqual( "Normal|+G1:______________________________________________________________+_", ReplaceIds(entries8[0].ToString()));
            Assert.AreEqual( "Normal|+G2:______________________________________________________________+_", ReplaceIds(entries8[1].ToString()));
            Assert.AreEqual("Sharing|+G1:_______________________________________________________________+", ReplaceIds(entries8[2].ToString()));
        }
        [TestMethod]
        public void Sharing_Acl_BreakAll_UndoBreak_NormalizeOne()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            SetMembership(ctx, "U1:G1,G2");

            SetAcl("+E1|Sharing|+G1:______________+");
            SetAcl("+E1| Normal|+G1:_____________+_");
            SetAcl("+E2| Normal|+G1:____________+__");
            SetAcl("+E3| Normal|+G2:_____________+_");

            var ed = ctx.CreateAclEditor();
            ed.BreakInheritance(Id("E5"), new[] { EntryType.Normal, EntryType.Sharing });
            ed.BreakInheritance(Id("E8"), new[] { EntryType.Normal, EntryType.Sharing });
            ed.Apply();

            // ACTION
            ed = ctx.CreateAclEditor();
            ed.UnBreakInheritance(Id("E5"), new[] { EntryType.Normal });
            ed.UnBreakInheritance(Id("E8"), new[] { EntryType.Normal });
            ed.Apply();

            // ASSERT
            var entries5 = ctx.GetExplicitEntries(Id("E5")); // E1/E2/E5
            var entries8 = ctx.GetExplicitEntries(Id("E8")); // E1/E3/E8

            Assert.AreEqual(1, entries5.Count);
            Assert.AreEqual("Sharing|+G1:_______________________________________________________________+", ReplaceIds(entries5[0].ToString()));

            Assert.AreEqual(1, entries8.Count);
            Assert.AreEqual("Sharing|+G1:_______________________________________________________________+", ReplaceIds(entries8[0].ToString()));
        }

        [TestMethod]
        public void Sharing_Acl_ExplicitEntries_NotMerged()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            SetMembership(ctx, "U1:G1");

            // ACTION 1
            SetAcl("+E1| Normal|+G1:_____________++");

            // ASSERT 1
            var storedAces = SecuritySystem.Instance.DataProvider.LoadAllAces().ToArray();
            Assert.AreEqual(1, storedAces.Length);
            Assert.AreEqual(EntryType.Normal, storedAces[0].EntryType);
            Assert.AreEqual(0x3ul, storedAces[0].AllowBits);

            var entries = ctx.GetExplicitEntries(Id("E1"));
            Assert.AreEqual(1, entries.Count);
            Assert.AreEqual(0x3ul, entries[0].AllowBits);
            Assert.AreEqual(EntryType.Normal, entries[0].EntryType);

            // ACTION 2
            SetAcl("+E1|Sharing|+G1:___________++__");

            // ASSERT 2
            storedAces = SecuritySystem.Instance.DataProvider.LoadAllAces().ToArray();
            Assert.AreEqual(2, storedAces.Length);
            Assert.AreEqual(0x3ul, storedAces[0].AllowBits);
            Assert.AreEqual(EntryType.Normal, storedAces[0].EntryType);
            Assert.AreEqual(0xCul, storedAces[1].AllowBits);
            Assert.AreEqual(EntryType.Sharing, storedAces[1].EntryType);

            entries = ctx.GetExplicitEntries(Id("E1"));
            Assert.AreEqual(2, entries.Count);
            Assert.AreEqual(0x3ul, entries[0].AllowBits);
            Assert.AreEqual(EntryType.Normal, entries[0].EntryType);
            Assert.AreEqual(0xCul, entries[1].AllowBits);
            Assert.AreEqual(EntryType.Sharing, entries[1].EntryType);
        }

        [TestMethod]
        public void Sharing_Acl_ExplicitEntries_Filtered()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            SetMembership(ctx, "U1:G1");

            SetAcl("+E1| Normal|+G1:______________+"); // 0x1
            SetAcl("+E1|Sharing|+G1:___________+___"); // 0x8
            SetAcl("+E2| Normal|+G1:_____________+_"); // 0x2
            SetAcl("+E2|Sharing|+G1:__________+____"); // 0x10
            SetAcl("+E2| Normal|-G1:____________+__"); // 0x4   local
            SetAcl("+E2|Sharing|-G1:_________+_____"); // 0x20  local

            // ACTION 1: query without filter + local entries
            var entries = ctx.GetExplicitEntries(Id("E2"))
                .OrderBy(x => x.LocalOnly).ThenBy(x => x.EntryType).ToList();
            // ASSERT 1
            Assert.AreEqual(4, entries.Count);
            Assert.AreEqual( "Normal|+G1:______________________________________________________________+_", ReplaceIds(entries[0].ToString()));
            Assert.AreEqual("Sharing|+G1:___________________________________________________________+____", ReplaceIds(entries[1].ToString()));
            Assert.AreEqual( "Normal|-G1:_____________________________________________________________+__", ReplaceIds(entries[2].ToString()));
            Assert.AreEqual("Sharing|-G1:__________________________________________________________+_____", ReplaceIds(entries[3].ToString()));

            // ACTION 2: query without filter, no local entries
            entries = ctx.GetExplicitEntries(Id("E1"))
                .OrderBy(x => x.LocalOnly).ThenBy(x => x.EntryType).ToList();
            // ASSERT 2
            Assert.AreEqual(2, entries.Count);
            Assert.IsTrue(!entries[0].LocalOnly && entries[0].EntryType == EntryType.Normal);
            Assert.IsTrue(!entries[1].LocalOnly && entries[1].EntryType == EntryType.Sharing);
            Assert.AreEqual( "Normal|+G1:_______________________________________________________________+", ReplaceIds(entries[0].ToString()));
            Assert.AreEqual("Sharing|+G1:____________________________________________________________+___", ReplaceIds(entries[1].ToString()));

            // ACTION 3: query + filter Normal + local entries
            entries = ctx.GetExplicitEntries(Id("E2"), null, EntryType.Normal)
                .OrderBy(x => x.LocalOnly).ThenBy(x => x.EntryType).ToList();
            // ASSERT 3
            Assert.AreEqual(2, entries.Count);
            Assert.AreEqual("Normal|+G1:______________________________________________________________+_", ReplaceIds(entries[0].ToString()));
            Assert.AreEqual("Normal|-G1:_____________________________________________________________+__", ReplaceIds(entries[1].ToString()));

            // ACTION 4: query + filter Sharing + local entries
            entries = ctx.GetExplicitEntries(Id("E2"), null, EntryType.Sharing)
                .OrderBy(x => x.LocalOnly).ThenBy(x => x.EntryType).ToList();
            // ASSERT 4
            Assert.AreEqual(2, entries.Count);
            Assert.AreEqual("Sharing|+G1:___________________________________________________________+____", ReplaceIds(entries[0].ToString()));
            Assert.AreEqual("Sharing|-G1:__________________________________________________________+_____", ReplaceIds(entries[1].ToString()));

            // ACTION 5: query + filter Normal, no local entries
            entries = ctx.GetExplicitEntries(Id("E1"), null, EntryType.Normal);
            // ASSERT 5
            Assert.AreEqual(1, entries.Count);
            Assert.AreEqual("Normal|+G1:_______________________________________________________________+", ReplaceIds(entries[0].ToString()));

            // ACTION 6: query + filter Sharing, no local entries
            entries = ctx.GetExplicitEntries(Id("E1"), null, EntryType.Sharing);
            // ASSERT 6
            Assert.AreEqual("Sharing|+G1:____________________________________________________________+___", ReplaceIds(entries[0].ToString()));
        }
        [TestMethod]
        public void Sharing_Acl_EffectiveEntries_Filtered()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            SetMembership(ctx, "U1:G1");

            SetAcl("+E1| Normal|+G1:______________+"); // 0x1
            SetAcl("+E1|Sharing|+G1:___________+___"); // 0x8
            SetAcl("+E2| Normal|+G1:_____________+_"); // 0x2
            SetAcl("+E2|Sharing|+G1:__________+____"); // 0x10
            SetAcl("+E2| Normal|-G1:____________+__"); // 0x4   local
            SetAcl("+E2|Sharing|-G1:_________+_____"); // 0x20  local

            // ACTION 1: query without filter + local entries
            var entries = ctx.GetEffectiveEntries(Id("E2"));
            // ASSERT 1
            Assert.AreEqual(4, entries.Count);
            Assert.AreEqual(2, entries.Count(x => x.EntryType == EntryType.Normal));
            Assert.AreEqual(2, entries.Count(x => x.EntryType == EntryType.Sharing));
            Assert.AreEqual(2, entries.Count(x => x.LocalOnly));
            Assert.AreEqual(2, entries.Count(x => !x.LocalOnly));

            // ACTION 2: query without filter, no local entries
            entries = ctx.GetEffectiveEntries(Id("E5"));
            // ASSERT 2
            Assert.AreEqual(2, entries.Count);
            Assert.AreEqual(1, entries.Count(x => x.EntryType == EntryType.Normal));
            Assert.AreEqual(1, entries.Count(x => x.EntryType == EntryType.Sharing));
            Assert.AreEqual(0, entries.Count(x => x.LocalOnly));
            Assert.AreEqual(2, entries.Count(x => !x.LocalOnly));

            // ACTION 3: query + filter Normal + local entries
            entries = ctx.GetEffectiveEntries(Id("E2"), null, EntryType.Normal);
            // ASSERT 3
            Assert.AreEqual(2, entries.Count);
            Assert.AreEqual(0x3ul, entries.First(x => !x.LocalOnly).AllowBits);
            Assert.AreEqual(0x4ul, entries.First(x => x.LocalOnly).AllowBits);
            Assert.AreEqual(EntryType.Normal, entries[0].EntryType);
            Assert.AreEqual(EntryType.Normal, entries[1].EntryType);

            // ACTION 4: query + filter Sharing + local entries
            entries = ctx.GetEffectiveEntries(Id("E2"), null, EntryType.Sharing);
            // ASSERT 4
            Assert.AreEqual(2, entries.Count);
            Assert.AreEqual(0x18ul, entries.First(x => !x.LocalOnly).AllowBits);
            Assert.AreEqual(0x20ul, entries.First(x => x.LocalOnly).AllowBits);
            Assert.AreEqual(EntryType.Sharing, entries[0].EntryType);
            Assert.AreEqual(EntryType.Sharing, entries[1].EntryType);

            // ACTION 5: query + filter Normal, no local entries
            entries = ctx.GetEffectiveEntries(Id("E5"), null, EntryType.Normal);
            // ASSERT 5
            Assert.AreEqual(1, entries.Count);
            Assert.AreEqual(0x3ul, entries[0].AllowBits);
            Assert.AreEqual(EntryType.Normal, entries[0].EntryType);

            // ACTION 6: query + filter Sharing, no local entries
            entries = ctx.GetEffectiveEntries(Id("E5"), null, EntryType.Sharing);
            // ASSERT 6
            Assert.AreEqual(1, entries.Count);
            Assert.AreEqual(0x18ul, entries[0].AllowBits);
            Assert.AreEqual(EntryType.Sharing, entries[0].EntryType);
        }

        [TestMethod]
        public void Sharing_AclEd_DefaultDoesNotSeeSharingEntries()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            SetMembership(ctx, "U1:G1");

            SetAcl("+E1| Normal|+G1:______________+");
            SetAcl("+E2|Sharing|+G1:____________+__");

            // ACTION 1
            var ed = ctx.CreateAclEditor();
            ed.Allow("E2", "G1", "_____________+_");

            // ASSERT 1 (edited entry is brand new so not merged with the existing sharing entry)
            var edAcls = new AclEditorAccessor(ed).Acls;
            Assert.AreEqual(Id("E2"), edAcls.Count == 0 ? 0 : edAcls.First().Key);
            var entry = edAcls[Id("E2")].Entries.FirstOrDefault();
            Assert.IsNotNull(entry);
            Assert.AreEqual(EntryType.Normal, entry.EntryType);
            Assert.AreEqual(0x2ul, entry.AllowBits);

            // ACTION 2
            ed.Apply();

            // ASSERT 2
            var eff = ctx.GetEffectiveEntries(Id("E2")).OrderBy(x => x.EntryType).ToList();
            Assert.AreEqual(2, eff.Count);
            Assert.AreEqual(0x3ul, eff[0].AllowBits);
            Assert.AreEqual(0x4ul, eff[1].AllowBits);

            var exp = ctx.GetExplicitEntries(Id("E2")).OrderBy(x => x.EntryType).ToList();
            Assert.AreEqual(2, exp.Count);
            Assert.AreEqual(0x2ul, exp[0].AllowBits);
            Assert.AreEqual(0x4ul, exp[1].AllowBits);
        }

        [TestMethod]
        public void Sharing_AclEd_SettingInconsistentEntryIsInvalidOperation()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;
            var normalEditor = ctx.CreateAclEditor();
            var sharingEditor = ctx.CreateAclEditor(EntryType.Sharing);
            var normalEntry = new AceInfo { EntryType = EntryType.Normal, IdentityId = Id("U1"), AllowBits = 0x1ul };
            var sharingEntry = new AceInfo { EntryType = EntryType.Sharing, IdentityId = Id("U2"), AllowBits = 0x2ul };

            // ACTION 1
            normalEditor.SetEntry(Id("E1"), normalEntry, false);
            try
            {
                normalEditor.SetEntry(Id("E1"), sharingEntry, false);
                Assert.Fail();
            }
            catch (InvalidOperationException)
            {
            }

            // ACTION 2
            sharingEditor.SetEntry(Id("E1"), sharingEntry, false);
            try
            {
                sharingEditor.SetEntry(Id("E1"), normalEntry, false);
                Assert.Fail();
            }
            catch (InvalidOperationException)
            {
            }
        }

        [TestMethod]
        public void Sharing_AclEd_SetBitmask()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            var bitMask = new PermissionBitMask { AllowBits = 0x1Ful, DenyBits = 0x00ul };
            ctx.CreateAclEditor(EntryType.Sharing)
                .Set(Id("E5"), Id("U1"), false, bitMask)
                .Apply();

            var entries = ctx.GetExplicitEntries(Id("E5"), null, EntryType.Sharing);
            Assert.AreEqual(1, entries.Count);
        }
    }
}