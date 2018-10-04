using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    public abstract partial class TestCases
    {
        [TestMethod]
        public void Sharing_GetAcl_Inheritance()
        {
            EnsureRepository();

            // Root permission for G1.
            SetAcl("+E1| Normal|+G1:______________+");
            // One level down: The sharing permits more.
            SetAcl("+E2|Sharing|+U1:____________+++");
            // Two level down: The sharing permits even more.
            SetAcl("+E5|Sharing|+U1:__________+++++");

            // Check under E2 but out from E5
            var acl = CurrentContext.Security.GetAcl(Id("E6"));
            Assert.AreEqual("+E6|Normal|+G1:_______________________________________________________________+," +
                               "Sharing|+U1:_____________________________________________________________+++", Tools.ReplaceIds(acl.ToString()));

            // Check under E2 and E5
            acl = CurrentContext.Security.GetAcl(Id("E14"));
            Assert.AreEqual("+E14|Normal|+G1:_______________________________________________________________+," +
                                "Sharing|+U1:___________________________________________________________+++++", Tools.ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Sharing_GetAcl_Local()
        {
            EnsureRepository();

            // Root permission for G1.
            SetAcl("+E1| Normal|+G1:______________+");
            // One level down: The sharing permits many more but only local.
            SetAcl("+E2|Sharing|-U1:________+++++++");
            // Two level down: The sharing permits less than on parent.
            SetAcl("+E5|Sharing|+U1:___________++++");

            // Check on E2
            var acl = CurrentContext.Security.GetAcl(Id("E2"));
            Assert.AreEqual("+E2|Normal|+G1:_______________________________________________________________+," +
                               "Sharing|-U1:_________________________________________________________+++++++", Tools.ReplaceIds(acl.ToString()));

            // Check under E2 but out from E5
            acl = CurrentContext.Security.GetAcl(Id("E6"));
            Assert.AreEqual("+E6|Normal|+G1:_______________________________________________________________+", Tools.ReplaceIds(acl.ToString()));

            // Check under E2 and E5
            acl = CurrentContext.Security.GetAcl(Id("E14"));
            Assert.AreEqual("+E14|Normal|+G1:_______________________________________________________________+," +
                                "Sharing|+U1:____________________________________________________________++++", Tools.ReplaceIds(acl.ToString()));
        }

        [TestMethod]
        public void Sharing_Eval_CheckPermissions()
        {
            EnsureRepository();
            Tools.SetMembership(CurrentContext.Security, "U1:G1");

            // Root permission for G1. The U1 is a member for it.
            SetAcl("+E1| Normal|+G1:_+_______________+"); // See + Run
            // One level down: The sharing permits many more but only local.
            SetAcl("+E2|Sharing|-U1:___________+++++++"); // Save
            // Two level down: The sharing permits less than on parent.
            SetAcl("+E5|Sharing|+U1:_____________+++++"); // Open

            PermissionValue see, open, save, run;
            var ctx = CurrentContext.Security;

            var entityId = Id("E1"); // Root
            see = ctx.GetPermission(entityId, PermissionType.See);
            open = ctx.GetPermission(entityId, PermissionType.Open);
            save = ctx.GetPermission(entityId, PermissionType.Save);
            run = ctx.GetPermission(entityId, PermissionType.RunApplication);
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

            Tools.SetMembership(ctx, "U1:G1");

            SetAcl("+E1|Sharing|+G1:______________+");
            SetAcl("-E2| Normal|+G1:_____________+_");

            Assert.IsFalse(ctx.HasPermission(Id("E2"), PermissionType.See));
            Assert.IsTrue(ctx.HasPermission(Id("E2"), PermissionType.Preview));
        }

        [TestMethod]
        public void Sharing_Acl_BreakOperation_SharingNotCopied()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            Tools.SetMembership(ctx, "U1:G1,G2");

            SetAcl("+E1|Sharing|+G1:______________+");
            SetAcl("+E2| Normal|+G1:_____________+_");
            SetAcl("+E3| Normal|+G2:_____________+_");

            // ACTION
            var ed = ctx.CreateAclEditor();
            ed.BreakInheritance(Id("E5"));
            ed.BreakInheritance(Id("E8"));
            ed.Apply();

            // ASSERT
            var acl14 = ctx.GetAcl(Id("E14")); // E1/E2/E5/E14
            var acl20 = ctx.GetAcl(Id("E20")); // E1/E3/E8/E20

            // original:     +E14|Normal|+G1:______________________________________________________________++
            Assert.AreEqual("+E14|Normal|+G1:______________________________________________________________+_", Tools.ReplaceIds(acl14.ToString()));

            // original:    <+E20|Normal|+G1:_______________________________________________________________+,
            //                    Normal|+G2:______________________________________________________________+_
            Assert.AreEqual("+E20|Normal|+G2:______________________________________________________________+_", Tools.ReplaceIds(acl20.ToString()));
        }
        [TestMethod]
        public void Sharing_Acl_ExplicitEntries_NotMerged()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            Tools.SetMembership(ctx, "U1:G1");

            // ACTION 1
            SetAcl("+E1| Normal|+G1:_____________++");

            // ASSERT 1
            var storedAces = ctx.DataProvider.LoadAllAces().ToArray();
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
            storedAces = ctx.DataProvider.LoadAllAces().ToArray();
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
        public void Sharing_Acl_EffectiveEntries_Merged()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            Tools.SetMembership(ctx, "U1:G1");

            // ACTION 1
            SetAcl("+E1| Normal|+G1:______________+");
            SetAcl("+E2| Normal|+G1:_____________+_");

            // ASSERT 1
            var entries = ctx.GetEffectiveEntries(Id("E2"));
            Assert.AreEqual(1, entries.Count);
            Assert.AreEqual(0x3ul, entries[0].AllowBits);
            Assert.AreEqual(EntryType.Normal, entries[0].EntryType);

            // ACTION 2
            SetAcl("+E1|Sharing|+G1:____________+__");

            // ASSERT 2
            entries = ctx.GetEffectiveEntries(Id("E2"));
            Assert.AreEqual(1, entries.Count);
            Assert.AreEqual(0x7ul, entries[0].AllowBits);
            Assert.AreEqual(EntryType.Normal, entries[0].EntryType);

            // ACTION 3
            SetAcl("+E2|Sharing|+G1:___________+___");

            // ASSERT 3
            entries = ctx.GetEffectiveEntries(Id("E2"));
            Assert.AreEqual(1, entries.Count);
            Assert.AreEqual(0xFul, entries[0].AllowBits);
            Assert.AreEqual(EntryType.Normal, entries[0].EntryType);
        }

        [TestMethod]
        public void Sharing_AclEd_DefaultDoesNotSeeSharingEntries()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            Tools.SetMembership(ctx, "U1:G1");

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
            var eff = ctx.GetEffectiveEntries(Id("E2"));
            Assert.AreEqual(1, eff.Count);
            Assert.AreEqual(0x7ul, eff[0].AllowBits);

            var exp = ctx.GetExplicitEntries(Id("E2"));
            Assert.AreEqual(2, exp.Count);
            Assert.AreEqual(0x2ul, exp.First(x => x.EntryType == EntryType.Normal).AllowBits);
            Assert.AreEqual(0x4ul, exp.First(x => x.EntryType == EntryType.Sharing).AllowBits);
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
    }
}