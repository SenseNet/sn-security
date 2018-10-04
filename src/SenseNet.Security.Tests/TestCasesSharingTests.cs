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
        public void Sharing_Eval_BreakOperation_SharingNotCopied()
        {
            EnsureRepository();
            var ctx = CurrentContext.Security;

            Tools.SetMembership(ctx, "U1:G1,G2");

            SetAcl("+E1|Sharing|+G1:______________+");
            SetAcl("+E2| Normal|+G1:_____________+_");
            SetAcl("+E3| Normal|+G2:_____________+_");

            // Action
            var ed = ctx.CreateAclEditor();
            ed.BreakInheritance(Id("E5"));
            ed.BreakInheritance(Id("E8"));
            ed.Apply();

            // Assert
            var acl14 = ctx.GetAcl(Id("E14")); // E1/E2/E5/E14
            var acl20 = ctx.GetAcl(Id("E20")); // E1/E3/E8/E20

            Assert.AreEqual("+E14|Normal|+G1:______________________________________________________________+_", Tools.ReplaceIds(acl14.ToString()));
            Assert.AreEqual("+E20|Normal|+G2:______________________________________________________________+_", Tools.ReplaceIds(acl20.ToString()));
        }
    }
}