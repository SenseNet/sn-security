using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using SenseNet.Security;
using SenseNet.Security.Data;
using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class AclTests
    {
        private Context __context;
        private Context CurrentContext { get { return __context; } }

        public TestContext TestContext { get; set; }

        [TestInitialize]
        public void StartTest()
        {
            __context = Tools.GetEmptyContext(TestUser.User1);
            EnsureRepository();
        }

        [TestCleanup]
        public void Finishtest()
        {
            Tools.CheckIntegrity(TestContext.TestName, CurrentContext.Security);
        }

        #region //======================================================================= Acl_Xx

        [TestMethod]
        public void Acl_Get0()
        {
            var acl = CurrentContext.Security.GetAclInfo(int.MaxValue, false);
            Assert.IsNull(acl);
        }
        [TestMethod]
        public void Acl_Get1()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:______________+");
            var acl = CurrentContext.Security.GetAcl(Id("E3"));
            Assert.AreEqual("+E3|+G1:_________________________________________________+++++++++++++++,+G2:_______________________________________________________________+", Tools.ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Acl_Get2()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");

            var acl = CurrentContext.Security.GetAcl(Id("E2"));
            Assert.AreEqual("+E2|+G1:_________________________________________________+++++++++++++++,+G2:_________________________________________________+-__________+++", Tools.ReplaceIds(acl.ToString()));

            acl = CurrentContext.Security.GetAcl(Id("E3"));
            Assert.AreEqual("+E3|+G1:_________________________________________________+++++++++++++++,+G2:__________________________________________________-____________+", Tools.ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Acl_Get3()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");
            SetAcl("+E3|+G3:+-+-+-+-+-+-+-+");

            var acl = CurrentContext.Security.GetAcl(Id("E3"));
            Assert.AreEqual("+E3|+G1:_________________________________________________+++++++++++++++,+G2:__________________________________________________-____________+,+G3:_________________________________________________+-+-+-+-+-+-+-+", Tools.ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Acl_Get4()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");
            CurrentContext.Security.BreakInheritance(Id("E3"), false);
            SetAcl("-E3|-G3:+-+-+-+-+-+-+-+");

            var acl = CurrentContext.Security.GetAcl(Id("E3"));

            Assert.AreEqual("-E3|-G3:_________________________________________________+-+-+-+-+-+-+-+", Tools.ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Acl_Get_BreakedEmpty()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");
            CurrentContext.Security.BreakInheritance(Id("E3"), false);

            var acl = CurrentContext.Security.GetAcl(Id("E3"));

            Assert.AreEqual("-E3|", Tools.ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Acl_Get_WithMembership()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1");
            Assert.IsTrue(CurrentContext.Security.Cache.IsInGroup(Id("U1"), Id("G1")), "G1 not contains U1");
            Assert.IsFalse(CurrentContext.Security.Cache.IsInGroup(int.MaxValue, int.MaxValue - 1), "Any group contains anyone");
            SetAcl("+E1|+U1:________---_+++,+G1:---_+++________");
            var acl = CurrentContext.Security.GetAcl(Id("E1"));
            Assert.AreEqual("+E1|+G1:_________________________________________________---_+++________,+U1:_________________________________________________________---_+++", Tools.ReplaceIds(acl.ToString()));

            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("______________+")));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("_____________+_")));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("____________+__")));

            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("___________+___")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("__________+____")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("_________+_____")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("________+______")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("_______+_______")));

            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("______+________")));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("_____+_________")));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("____+__________")));

            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("___+___________")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("__+____________")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("_+_____________")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), Tools.GetPermissionTypes("+______________")));
        }

        [TestMethod]
        public void Eval_HasPermission_Allow()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|+G1:______________+,+G2:_____________+_");
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.See, PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See, PermissionType.Preview));
            foreach (var perm in PermissionType.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), perm), String.Format("{0} permission on E1 is true, expected: false.", perm.Name));
                    Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E2"), perm), String.Format("{0} permission on E2 is true, expected: false.", perm.Name));
                }
            }
        }
        [TestMethod]
        public void Eval_HasPermission_Deny()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|+G1:+++++++++++++++,+G2:-------------++,+G3:+-+-+-+-+-+-+-+,-G4:+-+-+-+-+-+-+-+");
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.See, PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See, PermissionType.Preview));
            foreach (var perm in PermissionType.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), perm), String.Format("{0} permission on E1 is true, expected: false.", perm.Name));
                    Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E2"), perm), String.Format("{0} permission on E2 is true, expected: false.", perm.Name));
                }
            }
        }
        [TestMethod]
        public void Eval_AssertPermission()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|+G1:______________+,+G2:_____________+_");
            CurrentContext.Security.AssertPermission(Id("E1"), PermissionType.See);
            CurrentContext.Security.AssertPermission(Id("E1"), PermissionType.Preview);
            CurrentContext.Security.AssertPermission(Id("E1"), PermissionType.See, PermissionType.Preview);
            CurrentContext.Security.AssertPermission(Id("E2"), PermissionType.See);
            CurrentContext.Security.AssertPermission(Id("E2"), PermissionType.Preview);
            CurrentContext.Security.AssertPermission(Id("E2"), PermissionType.See, PermissionType.Preview);
            foreach (var perm in PermissionType.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    try
                    {
                        CurrentContext.Security.AssertPermission(Id("E1"), perm);
                        Assert.Fail(String.Format("{0} permission on E1 is true, expected: false.", perm.Name));
                    }
                    catch (AccessDeniedException) { }
                    try
                    {
                        CurrentContext.Security.AssertPermission(Id("E2"), perm);
                        Assert.Fail(String.Format("{0} permission on E2 is true, expected: false.", perm.Name));
                    }
                    catch (AccessDeniedException) { }
                }
            }
        }
        [TestMethod]
        public void Eval_AssertPermission3()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|+G1:______________+,+G2:_____________+_");

            var e1 = GetRepositoryEntity(Id("E1"));
            var e2 = GetRepositoryEntity(Id("E2"));

            CurrentContext.Security.AssertPermission(e1, PermissionType.See);
            CurrentContext.Security.AssertPermission(e1, PermissionType.Preview);
            CurrentContext.Security.AssertPermission(e1, PermissionType.See, PermissionType.Preview);
            CurrentContext.Security.AssertPermission(e2, PermissionType.See);
            CurrentContext.Security.AssertPermission(e2, PermissionType.Preview);
            CurrentContext.Security.AssertPermission(e2, PermissionType.See, PermissionType.Preview);
            foreach (var perm in PermissionType.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    try
                    {
                        CurrentContext.Security.AssertPermission(e1, perm);
                        Assert.Fail(String.Format("{0} permission on E1 is true, expected: false.", perm.Name));
                    }
                    catch (AccessDeniedException) { }
                    try
                    {
                        CurrentContext.Security.AssertPermission(e2, perm);
                        Assert.Fail(String.Format("{0} permission on E2 is true, expected: false.", perm.Name));
                    }
                    catch (AccessDeniedException) { }
                }
            }
        }
        [TestMethod]
        public void Eval_HasPermission_Break()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|+G1:______________+");
            SetAcl("-E2|+G1:_____________+_");
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.Preview));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See, PermissionType.Preview));
        }
        [TestMethod]
        public void Eval_HasPermission_LocalOnly()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|+G1:______________+");
            SetAcl("+E2|-G1:_____________+_");
            SetAcl("+E5|+G1:____________+__");

            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.Preview));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.PreviewWithoutWatermark));

            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E5"), PermissionType.See));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E5"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E5"), PermissionType.PreviewWithoutWatermark));
        }

        [TestMethod]
        public void Eval_HasSubtreePermission_Allow()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|+G1:______________+,+G2:_____________+_");
            SetAcl("+E3|+G1:_____________+_,+G2:______________+");
            SetAcl("+E9|+G3:___________+__+,+G4:_______+_____+_");
            SetAcl("+E20|+G3:_+___________+_,+G4:____+_________+");

            Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.See, PermissionType.Preview));

            foreach (var perm in PermissionType.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    Assert.IsFalse(CurrentContext.Security.HasSubtreePermission(Id("E1"), perm), String.Format("{0} subtree permission on E1 is true, expected: false.", perm.Name));
                    Assert.IsFalse(CurrentContext.Security.HasSubtreePermission(Id("E3"), perm), String.Format("{0} subtree permission on E3 is true, expected: false.", perm.Name));
                }
            }


            SetAcl("+E21|+G2:_____________-_,+G3:_+___________+_,+G4:____+________-+");

            //Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.Open));
            Assert.IsFalse(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.Preview));
            Assert.IsFalse(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.See, PermissionType.Preview));
        }
        [TestMethod]
        public void Eval_HasSubtreePermission_EmptySubTree_BugReproduction()
        {
            //E9 is an empty subtree (leaf) and has inherited permissions
            Tools.SetMembership(CurrentContext.Security, "U1:G1");
            CurrentContext.Security.CreateAclEditor()
                .Allow(Id("E1"), Id("G1"), false, PermissionType.See).Apply();          
            Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E9"), PermissionType.See));
        }       
        [TestMethod]
        public void Eval_AssertSubtreePermission()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|+G1:______________+,+G2:_____________+_");
            SetAcl("+E3|+G1:_____________+_,+G2:______________+");
            SetAcl("+E9|+G3:___________+__+,+G4:_______+_____+_");
            SetAcl("+E20|+G3:_+___________+_,+G4:____+_________+");

            var origOwnerId = Id("U1");
            var differentOwnerId = int.MaxValue;

            CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.See);
            CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.Preview);
            CurrentContext.Security.ModifyEntityOwner(Id("E3"), differentOwnerId);
            try
            {
                CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.See, PermissionType.Preview);
            }
            finally
            {
                CurrentContext.Security.ModifyEntityOwner(Id("E3"), origOwnerId);
            }

            foreach (var perm in PermissionType.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    try
                    {
                        CurrentContext.Security.AssertSubtreePermission(Id("E1"), perm);
                        Assert.Fail(String.Format("{0} subtree permission on E1 is true, expected: false.", perm.Name));
                    }
                    catch { }
                    try
                    {
                        CurrentContext.Security.ModifyEntityOwner(Id("E3"), differentOwnerId);
                        CurrentContext.Security.AssertSubtreePermission(Id("E3"), perm);
                        Assert.Fail(String.Format("{0} subtree permission on E3 is true, expected: false.", perm.Name));
                    }
                    catch { }
                    finally
                    {
                        CurrentContext.Security.ModifyEntityOwner(Id("E3"), origOwnerId);
                    }
                }
            }


            SetAcl("+E21|+G2:_____________-_,+G3:_+___________+_,+G4:____+________-+");

            try
            {
                CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.Preview);
                Assert.Fail("Edit subtree permission on E3 is true, expected: false.");
            }
            catch { }
            try
            {
                CurrentContext.Security.ModifyEntityOwner(Id("E3"), differentOwnerId);
                CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.See, PermissionType.Preview);
                Assert.Fail("Open+Edit subtree permission on E3 is true, expected: false.");
            }
            catch { }
            finally
            {
                CurrentContext.Security.ModifyEntityOwner(Id("E3"), origOwnerId);
            }
        }
        [TestMethod]
        public void Eval_AssertSubtreePermission_Entity()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|+G1:______________+,+G2:_____________+_");
            SetAcl("+E3|+G1:_____________+_,+G2:______________+");
            SetAcl("+E9|+G3:___________+__+,+G4:_______+_____+_");
            SetAcl("+E20|+G3:_+___________+_,+G4:____+_________+");

            var origOwnerId = Id("U1");
            var differentOwnerId = int.MaxValue;

            var e1 = GetRepositoryEntity(Id("E1"));
            var e3 = GetRepositoryEntity(Id("E3"));

            CurrentContext.Security.AssertSubtreePermission(e3, PermissionType.See);
            CurrentContext.Security.AssertSubtreePermission(e3, PermissionType.Preview);
            CurrentContext.Security.AssertSubtreePermission(e3, PermissionType.See, PermissionType.Preview);

            foreach (var perm in PermissionType.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    try
                    {
                        CurrentContext.Security.AssertSubtreePermission(e1, perm);
                        Assert.Fail(String.Format("{0} subtree permission on E1 is true, expected: false.", perm.Name));
                    }
                    catch { }
                    try
                    {
                        CurrentContext.Security.AssertSubtreePermission(e3, perm);
                        Assert.Fail(String.Format("{0} subtree permission on E3 is true, expected: false.", perm.Name));
                    }
                    catch { }
                }
            }


            SetAcl("+E21|+G2:_____________-_,+G3:_+___________+_,+G4:____+________-+");

            try
            {
                CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.Preview);
                Assert.Fail("Edit subtree permission on E3 is true, expected: false.");
            }
            catch { }
            try
            {
                CurrentContext.Security.ModifyEntityOwner(Id("E3"), differentOwnerId);
                CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.See, PermissionType.Preview);
                Assert.Fail("Open+Edit subtree permission on E3 is true, expected: false.");
            }
            catch { }
            finally
            {
                CurrentContext.Security.ModifyEntityOwner(Id("E3"), origOwnerId);
            }
        }
        [TestMethod]
        public void Eval_GetSubtreePermission_BreakAllowLocalonly()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|+G1:______________+,+G2:_____________+_");
            SetAcl("+E3|+G1:_____________+_,+G2:______________+");
            SetAcl("+E8|+G1:__________+++++,+U1:_________++++++");
            SetAcl("+E20|+G3:_+___________+_,+G4:____+_________+");
            SetAcl("-E21|+G1:__________+++++,-U1:_________++++++"); // on a node
            SetAcl("-E29|+G1:__________+++++,-U1:_________++++++"); // on a leaf

            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E8"), PermissionType.OpenMinor));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E21"), PermissionType.OpenMinor));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E22"), PermissionType.OpenMinor));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E29"), PermissionType.OpenMinor));

            // main tests
            Assert.IsFalse(CurrentContext.Security.HasSubtreePermission(Id("E8"), PermissionType.OpenMinor));
            Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E29"), PermissionType.OpenMinor));
        }

        [TestMethod]
        public void Eval_AssertChildPermission_ParentHasLocalOnlyEntry()
        {
            SetAcl("-E21|+G1:__________+++++,-G2:_________++++++");

            // E26 node is a child of E21 and it should not inherit its parent's local only entries
            Assert.AreEqual("+E26|+G1:___________________________________________________________+++++", 
                Tools.ReplaceIds(CurrentContext.Security.GetAcl(Id("E26")).ToString()));
        }

        [TestMethod]
        public void Eval_EffectivePermissions()
        {
            AclEditor ed;
            var db = CurrentContext.Security.DataProvider;

            var u1 = Id("U1");
            var u2 = Id("U2");
            var g1 = Id("G1");

            ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E1"), u1, false, Tools.GetPermissionTypes("_____________pp"));
            ed.Deny(Id("E1"), u1, false, Tools.GetPermissionTypes("____________p__"));
            ed.Allow(Id("E1"), u2, false, Tools.GetPermissionTypes("__________pp_pp"));
            ed.Deny(Id("E1"), u2, false, Tools.GetPermissionTypes("_________p__p__"));
            ed.Allow(Id("E2"), u1, false, Tools.GetPermissionTypes("__________pp___"));
            ed.Deny(Id("E2"), u1, false, Tools.GetPermissionTypes("_________p_____"));
            ed.Allow(Id("E2"), g1, false, Tools.GetPermissionTypes("__________pp_pp"));
            ed.Deny(Id("E2"), g1, false, Tools.GetPermissionTypes("_________p__p__"));
            ed.Allow(Id("E5"), u1, false, Tools.GetPermissionTypes("_______pp______"));
            ed.Deny(Id("E5"), u1, false, Tools.GetPermissionTypes("______p________"));
            ed.Allow(Id("E5"), u2, false, Tools.GetPermissionTypes("____pp_pp______"));
            ed.Deny(Id("E5"), u2, false, Tools.GetPermissionTypes("___p__p________"));
            ed.Allow(Id("E5"), g1, false, Tools.GetPermissionTypes("_pp_pp_pp______"));
            ed.Deny(Id("E5"), g1, false, Tools.GetPermissionTypes("p__p__p________"));
            ed.Apply();

            var entries = CurrentContext.Security.GetAclInfo(Id("E5")).GetEffectiveEntries(true);

            Assert.AreEqual(3, entries.Count);
            Assert.AreEqual("+G1:_________________________________________________-++-++-++-++-++", Tools.ReplaceIds(entries[0].ToString()));
            Assert.AreEqual("+U1:_______________________________________________________-++-++-++", Tools.ReplaceIds(entries[1].ToString()));
            Assert.AreEqual("+U2:____________________________________________________-++-++-++-++", Tools.ReplaceIds(entries[2].ToString()));
        }

        [TestMethod]
        public void AclEditor_PermissionBitMask1()
        {
            PermissionBitMask pbm;

            pbm = PermissionType.See;
            Assert.AreEqual(PermissionType.See.Mask, pbm.AllowBits);
            Assert.AreEqual(0u, pbm.DenyBits);

            pbm = ~PermissionType.Preview;
            Assert.AreEqual(0u, pbm.AllowBits);
            Assert.AreEqual(PermissionType.Preview.Mask, pbm.DenyBits);

            pbm = PermissionType.See | PermissionType.Preview;
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask, pbm.AllowBits);
            Assert.AreEqual(0u, pbm.DenyBits);

            pbm = ~PermissionType.See | PermissionType.Preview;
            Assert.AreEqual(PermissionType.Preview.Mask, pbm.AllowBits);
            Assert.AreEqual(PermissionType.See.Mask, pbm.DenyBits);

            pbm = ~PermissionType.See | ~PermissionType.Preview;
            Assert.AreEqual(0u, pbm.AllowBits);
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask, pbm.DenyBits);

            pbm = PermissionType.See | PermissionType.Preview | PermissionType.PreviewWithoutWatermark | ~PermissionType.Publish | ~PermissionType.Delete;
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask | PermissionType.PreviewWithoutWatermark.Mask, pbm.AllowBits);
            Assert.AreEqual(PermissionType.Publish.Mask | PermissionType.Delete.Mask, pbm.DenyBits);
        }

        [TestMethod]
        public void AclEditor_CreationPossibilities()
        {
            AclEditor ed;

            ed = AclEditor.Create(CurrentContext.Security);
            ed = new AclEditor(CurrentContext.Security);
            ed = CurrentContext.Security.CreateAclEditor();
        }
        [TestMethod]
        public void AclEditor_AllowDenyClear()
        {
            var entity = CurrentContext.Security.GetSecurityEntity(Id("E1"));
            var ed = CurrentContext.Security.CreateAclEditor();
            var edAcc = new PrivateObject(ed);
            var acls = (Dictionary<int, AclInfo>)edAcc.GetField("_acls");
            var userId = Id("U1");
            var ace = new AceInfo { IdentityId = userId };
            var level = entity.Level;
            var acl = new AclInfo(entity.Id);
            acl.Entries.Add(ace);
            acls[entity.Id] = acl;
            foreach (var permType in PermissionTypeBase.GetPermissionTypes())
            {
                ace.AllowBits = 0ul;
                ace.DenyBits = 0ul;
                ed.Allow(entity.Id, userId, false, permType);
                Assert.AreEqual(permType.Mask, ace.AllowBits);
                Assert.AreEqual(0u, ace.DenyBits);

                ace.AllowBits = 0ul;
                ace.DenyBits = 0ul;
                ed.Deny(entity.Id, userId, false, permType);
                Assert.AreEqual(0u, ace.AllowBits);
                Assert.AreEqual(permType.Mask, ace.DenyBits);

                ace.AllowBits = ~0ul;
                ace.DenyBits = ~0ul;
                ed.ClearPermission(entity.Id, userId, false, permType);
                Assert.AreEqual(~permType.Mask, ace.AllowBits);
                Assert.AreEqual(~permType.Mask, ace.DenyBits);
            }
        }
        [TestMethod]
        public void AclEditor_AllowDenyMoreBits()
        {
            var entityId = CurrentContext.Security.GetSecurityEntity(Id("E1")).Id;
            var userId1 = Id("U1");
            var userId2 = Id("U2");

            var ed = CurrentContext.Security.CreateAclEditor();
            var edAcc = new PrivateObject(ed);
            var acls = (Dictionary<int, AclInfo>)edAcc.GetField("_acls");

            ed.Allow(entityId, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark);
            ed.Allow(entityId, userId2, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark);
            ed.Allow(entityId, userId1, true, PermissionType.PreviewWithoutRedaction, PermissionType.Open);
            ed.Allow(entityId, userId2, true, PermissionType.PreviewWithoutRedaction, PermissionType.Open);
            ed.Deny(entityId, userId1, false, PermissionType.Publish, PermissionType.Delete);
            ed.Deny(entityId, userId2, false, PermissionType.Publish, PermissionType.Delete);
            ed.Deny(entityId, userId1, true, PermissionType.DeleteOldVersion, PermissionType.RecallOldVersion);
            ed.Deny(entityId, userId2, true, PermissionType.DeleteOldVersion, PermissionType.RecallOldVersion);

            var acl = acls[entityId];
            var aces = acl.Entries;

            Assert.AreEqual(4, aces.Count);

            var ace1 = aces.Where(x => x.IdentityId == userId1 && x.LocalOnly == false).FirstOrDefault();
            var ace2 = aces.Where(x => x.IdentityId == userId2 && x.LocalOnly == false).FirstOrDefault();
            var ace3 = aces.Where(x => x.IdentityId == userId1 && x.LocalOnly == true).FirstOrDefault();
            var ace4 = aces.Where(x => x.IdentityId == userId2 && x.LocalOnly == true).FirstOrDefault();

            Assert.AreEqual(userId1, ace1.IdentityId);
            Assert.AreEqual(false, ace1.LocalOnly);
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask | PermissionType.PreviewWithoutWatermark.Mask, ace1.AllowBits);
            Assert.AreEqual(PermissionType.Publish.Mask | PermissionType.Delete.Mask, ace1.DenyBits);

            Assert.AreEqual(userId2, ace2.IdentityId);
            Assert.AreEqual(false, ace2.LocalOnly);
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask | PermissionType.PreviewWithoutWatermark.Mask, ace2.AllowBits);
            Assert.AreEqual(PermissionType.Publish.Mask | PermissionType.Delete.Mask, ace2.DenyBits);

            Assert.AreEqual(userId1, ace3.IdentityId);
            Assert.AreEqual(true, ace3.LocalOnly);
            Assert.AreEqual(PermissionType.PreviewWithoutRedaction.Mask | PermissionType.Open.Mask, ace3.AllowBits);
            Assert.AreEqual(PermissionType.DeleteOldVersion.Mask | PermissionType.RecallOldVersion.Mask, ace3.DenyBits);

            Assert.AreEqual(userId2, ace4.IdentityId);
            Assert.AreEqual(true, ace4.LocalOnly);
            Assert.AreEqual(PermissionType.PreviewWithoutRedaction.Mask | PermissionType.Open.Mask, ace4.AllowBits);
            Assert.AreEqual(PermissionType.DeleteOldVersion.Mask | PermissionType.RecallOldVersion.Mask, ace4.DenyBits);
        }
        [TestMethod]
        public void AclEditor_AllowDenyAll()
        {
            CurrentContext.Security.CreateAclEditor().Set(Id("E1"), Id("U1"), false, new PermissionBitMask { AllowBits = ~0ul, DenyBits = 0ul }).Apply();
            Assert.AreEqual("+E1|+U1:++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E1")).ToString()));

            CurrentContext.Security.CreateAclEditor().Set(Id("E1"), Id("U1"), false, new PermissionBitMask { AllowBits = 0ul, DenyBits = ~0ul }).Apply();
            Assert.AreEqual("+E1|+U1:----------------------------------------------------------------", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E1")).ToString()));
        }
        [TestMethod]
        public void AclEditor_SetMoreBits()
        {
            var entityId = CurrentContext.Security.GetSecurityEntity(Id("E1")).Id;
            var userId1 = Id("U1");
            var userId2 = Id("U2");

            var ed = CurrentContext.Security.CreateAclEditor();
            var edAcc = new PrivateObject(ed);
            var acls = (Dictionary<int, AclInfo>)edAcc.GetField("_acls");

            //#
            ed.Set(entityId, userId1, false, PermissionType.See | PermissionType.Preview | PermissionType.PreviewWithoutWatermark | ~PermissionType.Publish | ~PermissionType.Delete);
            ed.Set(entityId, userId2, false, PermissionType.See | PermissionType.Preview | PermissionType.PreviewWithoutWatermark | ~PermissionType.Publish | ~PermissionType.Delete);
            ed.Set(entityId, userId1, true, PermissionType.PreviewWithoutRedaction | PermissionType.Open | ~PermissionType.DeleteOldVersion | ~PermissionType.RecallOldVersion);
            ed.Set(entityId, userId2, true, PermissionType.PreviewWithoutRedaction | PermissionType.Open | ~PermissionType.DeleteOldVersion | ~PermissionType.RecallOldVersion);

            var acl = acls[entityId];
            var aces = acl.Entries;

            Assert.AreEqual(4, aces.Count);

            var ace1 = aces.Where(x => x.IdentityId == userId1 && x.LocalOnly == false).FirstOrDefault();
            var ace2 = aces.Where(x => x.IdentityId == userId2 && x.LocalOnly == false).FirstOrDefault();
            var ace3 = aces.Where(x => x.IdentityId == userId1 && x.LocalOnly == true).FirstOrDefault();
            var ace4 = aces.Where(x => x.IdentityId == userId2 && x.LocalOnly == true).FirstOrDefault();

            Assert.AreEqual(userId1, ace1.IdentityId);
            Assert.AreEqual(false, ace1.LocalOnly);
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask | PermissionType.PreviewWithoutWatermark.Mask, ace1.AllowBits);
            Assert.AreEqual(PermissionType.Publish.Mask | PermissionType.Delete.Mask, ace1.DenyBits);

            Assert.AreEqual(userId2, ace2.IdentityId);
            Assert.AreEqual(false, ace2.LocalOnly);
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask | PermissionType.PreviewWithoutWatermark.Mask, ace2.AllowBits);
            Assert.AreEqual(PermissionType.Publish.Mask | PermissionType.Delete.Mask, ace2.DenyBits);

            Assert.AreEqual(userId1, ace3.IdentityId);
            Assert.AreEqual(true, ace3.LocalOnly);
            Assert.AreEqual(PermissionType.PreviewWithoutRedaction.Mask | PermissionType.Open.Mask, ace3.AllowBits);
            Assert.AreEqual(PermissionType.DeleteOldVersion.Mask | PermissionType.RecallOldVersion.Mask, ace3.DenyBits);

            Assert.AreEqual(userId2, ace4.IdentityId);
            Assert.AreEqual(true, ace4.LocalOnly);
            Assert.AreEqual(PermissionType.PreviewWithoutRedaction.Mask | PermissionType.Open.Mask, ace4.AllowBits);
            Assert.AreEqual(PermissionType.DeleteOldVersion.Mask | PermissionType.RecallOldVersion.Mask, ace4.DenyBits);
        }
        [TestMethod]
        public void AclEditor_AllowMoreEntriesInOneEditor()
        {
            var entityId1 = CurrentContext.Security.GetSecurityEntity(Id("E1")).Id;
            var entityId2 = CurrentContext.Security.GetSecurityEntity(Id("E2")).Id;
            var userId1 = Id("U1");
            var userId2 = Id("U2");

            var ed = CurrentContext.Security.CreateAclEditor();

            ed.Allow(entityId1, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark);
            ed.Allow(entityId1, userId2, false, PermissionType.See);
            ed.Allow(entityId2, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark, PermissionType.PreviewWithoutRedaction);
            ed.Apply();

            var acl = CurrentContext.Security.GetAcl(entityId2);
            Assert.AreEqual("+E2|+U1:____________________________________________________________++++,+U2:_______________________________________________________________+", Tools.ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void AclEditor_RemovePermissions()
        {
            var entityId1 = CurrentContext.Security.GetSecurityEntity(Id("E1")).Id;
            var entityId2 = CurrentContext.Security.GetSecurityEntity(Id("E2")).Id;
            var userId1 = Id("U1");
            var userId2 = Id("U2");

            var ed = CurrentContext.Security.CreateAclEditor();

            ed.Allow(entityId1, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark);
            ed.Allow(entityId1, userId2, false, PermissionType.See);
            ed.Allow(entityId2, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark, PermissionType.PreviewWithoutRedaction);
            ed.Apply();

            var acl = CurrentContext.Security.GetAcl(entityId2);
            Assert.AreEqual("+E2|+U1:____________________________________________________________++++,+U2:_______________________________________________________________+", Tools.ReplaceIds(acl.ToString()));

            //#
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(entityId2, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark, PermissionType.PreviewWithoutRedaction);
            ed.Apply();

            acl = CurrentContext.Security.GetAcl(entityId2);
            Assert.AreEqual("+E2|+U1:_____________________________________________________________+++,+U2:_______________________________________________________________+", Tools.ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void AclEditor_ResetPermissions()
        {
            var entityId1 = CurrentContext.Security.GetSecurityEntity(Id("E1")).Id;
            var entityId2 = CurrentContext.Security.GetSecurityEntity(Id("E2")).Id;
            var userId1 = Id("U1");
            var userId2 = Id("U2");

            var ed = CurrentContext.Security.CreateAclEditor();

            ed.Allow(entityId1, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark);
            ed.Allow(entityId1, userId2, false, PermissionType.See);
            ed.Allow(entityId2, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark, PermissionType.PreviewWithoutRedaction);
            ed.Apply();

            var acl = CurrentContext.Security.GetAcl(entityId2);
            Assert.AreEqual("+E2|+U1:____________________________________________________________++++,+U2:_______________________________________________________________+", Tools.ReplaceIds(acl.ToString()));

            //#
            ed = CurrentContext.Security.CreateAclEditor();
            ed.Reset(entityId2, userId1, false, PermissionType.See | PermissionType.Preview | PermissionType.PreviewWithoutWatermark | PermissionType.PreviewWithoutRedaction);
            ed.Apply();

            acl = CurrentContext.Security.GetAcl(entityId2);
            Assert.AreEqual("+E2|+U1:_____________________________________________________________+++,+U2:_______________________________________________________________+", Tools.ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void AclEditor_KeepInheritedPermissions()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1");

            var uid1 = Id("U1");
            var gid1 = Id("G1");

            var ed0 = CurrentContext.Security.CreateAclEditor();
            ed0.Allow(Id("E1"), Id("U1"), false, Tools.GetPermissionTypes("______________p"));
            ed0.Allow(Id("E2"), Id("U1"), false, Tools.GetPermissionTypes("_____________p_"));
            ed0.Allow(Id("E5"), Id("U1"), false, Tools.GetPermissionTypes("____________p__"));
            ed0.Allow(Id("E14"), Id("U1"), false, Tools.GetPermissionTypes("___________p___"));
            ed0.Allow(Id("E50"), Id("U1"), false, Tools.GetPermissionTypes("__________p____"));
            ed0.Allow(Id("E51"), Id("U1"), false, Tools.GetPermissionTypes("_________p_____"));
            ed0.Allow(Id("E1"), Id("G1"), false, Tools.GetPermissionTypes("______p________"));
            ed0.Allow(Id("E2"), Id("G1"), false, Tools.GetPermissionTypes("_____p_________"));
            ed0.Allow(Id("E5"), Id("G1"), false, Tools.GetPermissionTypes("____p__________"));
            ed0.Allow(Id("E14"), Id("G1"), false, Tools.GetPermissionTypes("___p___________"));
            ed0.Allow(Id("E50"), Id("G1"), false, Tools.GetPermissionTypes("__p____________"));
            ed0.Allow(Id("E51"), Id("G1"), false, Tools.GetPermissionTypes("_p_____________"));
            ed0.Apply();
            Assert.AreEqual("__________________________________________________++++++__++++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# set some new and more irrelevant permissions
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.Deny(Id("E52"), uid1, false, Tools.GetPermissionTypes("________ppppppp"));
            ed.Deny(Id("E52"), gid1, false, Tools.GetPermissionTypes("ppppppp________"));
            ed.Apply();
            Assert.AreEqual("_________________________________________________-------_-------", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E52"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E52"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();
            Assert.AreEqual("__________________________________________________++++++__++++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E51"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E51"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();
            Assert.AreEqual("___________________________________________________+++++___+++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E50"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E50"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();
            Assert.AreEqual("____________________________________________________++++____++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E1"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E1"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();
            Assert.AreEqual("____________________________________________________+++_____+++_", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E2"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E2"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();
            Assert.AreEqual("____________________________________________________++______++__", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E5"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E5"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();
            Assert.AreEqual("____________________________________________________+_______+___", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E14"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E14"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();
            Assert.AreEqual("________________________________________________________________", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));
        }
        [TestMethod]
        public void AclEditor_KeepInheritedPermissions_CommonAclEditor()
        {
            Tools.SetMembership(CurrentContext.Security, "U1:G1");

            var uid1 = Id("U1");
            var gid1 = Id("G1");

            var ed0 = CurrentContext.Security.CreateAclEditor();
            ed0.Allow(Id("E1"), Id("U1"), false, Tools.GetPermissionTypes("______________p"));
            ed0.Allow(Id("E2"), Id("U1"), false, Tools.GetPermissionTypes("_____________p_"));
            ed0.Allow(Id("E5"), Id("U1"), false, Tools.GetPermissionTypes("____________p__"));
            ed0.Allow(Id("E14"), Id("U1"), false, Tools.GetPermissionTypes("___________p___"));
            ed0.Allow(Id("E50"), Id("U1"), false, Tools.GetPermissionTypes("__________p____"));
            ed0.Allow(Id("E51"), Id("U1"), false, Tools.GetPermissionTypes("_________p_____"));
            ed0.Allow(Id("E1"), Id("G1"), false, Tools.GetPermissionTypes("______p________"));
            ed0.Allow(Id("E2"), Id("G1"), false, Tools.GetPermissionTypes("_____p_________"));
            ed0.Allow(Id("E5"), Id("G1"), false, Tools.GetPermissionTypes("____p__________"));
            ed0.Allow(Id("E14"), Id("G1"), false, Tools.GetPermissionTypes("___p___________"));
            ed0.Allow(Id("E50"), Id("G1"), false, Tools.GetPermissionTypes("__p____________"));
            ed0.Allow(Id("E51"), Id("G1"), false, Tools.GetPermissionTypes("_p_____________"));
            ed0.Apply();
            Assert.AreEqual("__________________________________________________++++++__++++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# set some new and more irrelevant permissions
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.Deny(Id("E52"), uid1, false, Tools.GetPermissionTypes("________ppppppp"));
            ed.Deny(Id("E52"), gid1, false, Tools.GetPermissionTypes("ppppppp________"));
            ed.Apply();
            Assert.AreEqual("_________________________________________________-------_-------", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E52"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E52"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();
            Assert.AreEqual("__________________________________________________++++++__++++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E51"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E51"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E50"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E50"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E1"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E1"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E2"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E2"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E5"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E5"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();
            Assert.AreEqual("____________________________________________________+_______+___", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));
            Assert.AreEqual(default(int), CurrentContext.Security.Cache.Entities[Id("E5")].GetFirstAclId());

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E14"), uid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E14"), gid1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();
            Assert.AreEqual("________________________________________________________________", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default(int)));
        }
        [TestMethod]
        public void AclEditor_EmptyEntriesRemovedFromDatabase()
        {
            var u1 = Id("U1");

            var ed0 = CurrentContext.Security.CreateAclEditor();
            ed0.Allow(Id("E1"), u1, false, Tools.GetPermissionTypes("________p_p_p_p"));
            ed0.Deny(Id("E1"), u1, false, Tools.GetPermissionTypes("_______p_p_p_p_"));
            ed0.Allow(Id("E2"), u1, false, Tools.GetPermissionTypes("p_p_p_p________"));
            ed0.Deny(Id("E2"), u1, false, Tools.GetPermissionTypes("_p_p_p_________"));
            ed0.Apply();

            Assert.AreEqual("_________________________________________________+-+-+-+-+-+-+-+", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E5"), u1, default(int)));
            var dbentries1 = Tools.PeekEntriesFromTestDatabase(Id("E1"), (MemoryDataProvider)CurrentContext.Security.DataProvider);
            var dbentries2 = Tools.PeekEntriesFromTestDatabase(Id("E2"), (MemoryDataProvider)CurrentContext.Security.DataProvider);
            Assert.AreEqual(1, dbentries1.Count());
            Assert.AreEqual(1, dbentries2.Count());

            //# clear all permissions (inherited won't be cleared)
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E2"), u1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();

            Assert.AreEqual("________________________________________________________-+-+-+-+", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), u1, default(int)));
            dbentries1 = Tools.PeekEntriesFromTestDatabase(Id("E1"), (MemoryDataProvider)CurrentContext.Security.DataProvider);
            dbentries2 = Tools.PeekEntriesFromTestDatabase(Id("E2"), (MemoryDataProvider)CurrentContext.Security.DataProvider);
            Assert.AreEqual(1, dbentries1.Count());
            Assert.AreEqual(0, dbentries2.Count());
        }
        [TestMethod]
        public void AclEditor_EmptyEntriesRemovedFromMemory()
        {
            var u1 = Id("U1");

            var ed0 = CurrentContext.Security.CreateAclEditor();
            ed0.Allow(Id("E1"), u1, false, Tools.GetPermissionTypes("________p_p_p_p"));
            ed0.Deny(Id("E1"), u1, false, Tools.GetPermissionTypes("_______p_p_p_p_"));
            ed0.Allow(Id("E2"), u1, false, Tools.GetPermissionTypes("p_p_p_p________"));
            ed0.Deny(Id("E2"), u1, false, Tools.GetPermissionTypes("_p_p_p_________"));
            ed0.Apply();

            var acl1 = CurrentContext.Security.GetAclInfo(Id("E1"));
            var acl2 = CurrentContext.Security.GetAclInfo(Id("E2"));
            Assert.AreEqual(1, acl1.Entries.Count);
            Assert.AreEqual(1, acl2.Entries.Count);

            //# clear all permissions (inherited won't be cleared)
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E2"), u1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();

            acl1 = CurrentContext.Security.GetAclInfo(Id("E1"));
            acl2 = CurrentContext.Security.GetAclInfo(Id("E2"));
            Assert.AreEqual(1, acl1.Entries.Count);
            Assert.IsNull(acl2);
        }
        [TestMethod]
        public void AclEditor_BreakedEmptyAclIsNotDeletedFromMemory()
        {
            var u1 = Id("U1");

            var ed0 = CurrentContext.Security.CreateAclEditor();
            ed0.Allow(Id("E1"), u1, false, Tools.GetPermissionTypes("________p_p_p_p"));
            ed0.Deny(Id("E1"), u1, false, Tools.GetPermissionTypes("_______p_p_p_p_"));
            ed0.Allow(Id("E2"), u1, false, Tools.GetPermissionTypes("p_p_p_p________"));
            ed0.Deny(Id("E2"), u1, false, Tools.GetPermissionTypes("_p_p_p_________"));
            ed0.Apply();

            var acl1 = CurrentContext.Security.GetAclInfo(Id("E1"));
            var acl2 = CurrentContext.Security.GetAclInfo(Id("E2"));
            Assert.AreEqual(1, acl1.Entries.Count);
            Assert.AreEqual(1, acl2.Entries.Count);

            //# clear all permissions (inherited won't be cleared)
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.BreakInheritance(Id("E2"));

            ed.ClearPermission(Id("E2"), u1, false, Tools.GetPermissionTypes("ppppppppppppppp"));
            ed.Apply();

            acl1 = CurrentContext.Security.GetAclInfo(Id("E1"));
            acl2 = CurrentContext.Security.GetAclInfo(Id("E2"));
            Assert.AreEqual(1, acl1.Entries.Count);
            Assert.AreEqual(0, acl2.Entries.Count);
            Assert.AreEqual(false, acl2.Inherits);
        }

        [TestMethod]
        public void AclEditor_UseLocalOnlyValues()
        {
            var u1 = Id("U1");

            var ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E1"), u1, false, Tools.GetPermissionTypes("______________p"));
            ed.Allow(Id("E2"), u1, true, Tools.GetPermissionTypes("_____________p_"));
            ed.Allow(Id("E5"), u1, false, Tools.GetPermissionTypes("____________p__"));
            ed.Allow(Id("E14"), u1, false, Tools.GetPermissionTypes("___________p___"));
            ed.Deny(Id("E1"), u1, false, Tools.GetPermissionTypes("______p________"));
            ed.Deny(Id("E2"), u1, false, Tools.GetPermissionTypes("_____p_________"));
            ed.Deny(Id("E5"), u1, true, Tools.GetPermissionTypes("____p__________"));
            ed.Deny(Id("E14"), u1, false, Tools.GetPermissionTypes("___p___________"));
            ed.Apply();

            Assert.AreEqual("_______________________________________________________-_______+", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E1"), u1, default(int)));
            Assert.AreEqual("______________________________________________________--______++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E2"), u1, default(int)));
            Assert.AreEqual("_____________________________________________________---_____+_+", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E5"), u1, default(int)));
            Assert.AreEqual("____________________________________________________-_--____++_+", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E14"), u1, default(int)));
        }
        [TestMethod]
        public void AclEditor_NearestHolderId()
        {
            AclEditor ed;
            var sec = CurrentContext.Security;
            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);

            var u1 = Id("U1");
            var eid0 = default(int);
            var eid1 = Id("E1");
            var eid2 = Id("E2");
            var eid3 = Id("E3");
            var eid5 = Id("E5");
            var eid14 = Id("E14");
            var eid15 = Id("E15");
            var eid17 = Id("E17");

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E2"), u1, false, Tools.GetPermissionTypes("_____________P_"));
            ed.Apply();

            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid17).GetFirstAclId());

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E1"), u1, false, Tools.GetPermissionTypes("______________p"));
            ed.Apply();

            Assert.AreEqual(eid1, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid1, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid17).GetFirstAclId());

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E5"), u1, false, Tools.GetPermissionTypes("____________P__"));
            ed.Apply();

            Assert.AreEqual(eid1, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid1, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid17).GetFirstAclId());

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E1"), u1, false, Tools.GetPermissionTypes("______________P"));
            ed.Apply();

            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid17).GetFirstAclId());

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E5"), u1, false, Tools.GetPermissionTypes("____________P__"));
            ed.Apply();

            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid17).GetFirstAclId());

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E2"), u1, false, Tools.GetPermissionTypes("_____________P_"));
            ed.Apply();

            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid17).GetFirstAclId());
        }
        [TestMethod]
        public void AclEditor_EditablePermissions()
        {
            AclEditor ed;
            var db = CurrentContext.Security.DataProvider;

            var u1 = Id("U1");

            ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E1"), u1, false, Tools.GetPermissionTypes("____________ppp"));
            ed.Allow(Id("E2"), u1, false, Tools.GetPermissionTypes("_________ppp___"));
            ed.Allow(Id("E5"), u1, false, Tools.GetPermissionTypes("______ppp______"));
            ed.Apply();

            var acl = CurrentContext.Security.GetAcl(Id("E1"));
            Assert.AreEqual(64, acl.Entries.First().Permissions.Where(x => x.AllowFrom == default(int) && x.DenyFrom == default(int)).Count());

            acl = CurrentContext.Security.GetAcl(Id("E2"));
            Assert.AreEqual(61, acl.Entries.First().Permissions.Where(x => x.AllowFrom == default(int) && x.DenyFrom == default(int)).Count());

            acl = CurrentContext.Security.GetAcl(Id("E5"));
            Assert.AreEqual(58, acl.Entries.First().Permissions.Where(x => x.AllowFrom == default(int) && x.DenyFrom == default(int)).Count());

            acl = CurrentContext.Security.GetAcl(Id("E14"));
            Assert.AreEqual(55, acl.Entries.First().Permissions.Where(x => x.AllowFrom == default(int) && x.DenyFrom == default(int)).Count());
        }



        [TestMethod]
        public void AclEditor_BreakInheritance_NotHolder_WithCopy()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E5")).Apply();

            Assert.AreEqual("-E5|+G1:_________________________________________________+++++++++++++++,+G2:_________________________________________________+-__________+++", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E5"));
            Assert.IsFalse(entity.IsInherited);

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(2, aces.Length);
            Assert.AreEqual("E5|+G1:_________________________________________________+++++++++++++++", Tools.ReplaceIds(aces[0].ToString()));
            Assert.AreEqual("E5|+G2:_________________________________________________+-__________+++", Tools.ReplaceIds(aces[1].ToString()));
        }
        [TestMethod]
        public void AclEditor_BreakInheritance_Holder_WithCopy()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E2")).Apply();

            var aclInfo = CurrentContext.Security.GetAclInfo(Id("E2"));
            Assert.IsNotNull(aclInfo);
            Assert.AreEqual("-E2|+G1:_________________________________________________+++++++++++++++,+G2:_________________________________________________+-__________+++", Tools.ReplaceIds(aclInfo.ToString()));

            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E2"));
            Assert.IsFalse(entity.IsInherited);

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E2")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(2, aces.Length);
            Assert.AreEqual("E2|+G1:_________________________________________________+++++++++++++++", Tools.ReplaceIds(aces[0].ToString()));
            Assert.AreEqual("E2|+G2:_________________________________________________+-__________+++", Tools.ReplaceIds(aces[1].ToString()));
        }
        [TestMethod]
        public void AclEditor_BreakInheritance_NotHolder_WithoutCopy()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E5"), false).Apply();

            var aclInfo = CurrentContext.Security.GetAclInfo(Id("E5"));
            Assert.IsNotNull(aclInfo);
            Assert.AreEqual("-E5|", Tools.ReplaceIds(aclInfo.ToString()));

            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E5"));
            Assert.IsFalse(entity.IsInherited);

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(0, aces.Length);
        }
        [TestMethod]
        public void AclEditor_BreakInheritance_NotHolder_WithoutCopy_ChildrenAcls()
        {
            //Break on E32
            //Expected:
            //  children acls: E35, E36
            //  not children acls: E33, E34

            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");                              // 0x01        // 0x01
            SetAcl("+E12|+G2:+___________++_");                                                 //   0x0C      //   0x0C
            SetAcl("+E33|+G2:_+++++++++++___");                                                 //     0x21    //     0x21
            SetAcl("+E34|+G2:_+++++++++++___");                                                 //     0x22    //     0x22
            SetAcl("+E35|+G2:_+++++++++++___");                                                 //     0x23    //     0x20  0x23
            SetAcl("+E36|+G2:_+++++++++++___");                                                 //     0x24    //           0x24

            var ctx =  CurrentContext.Security;
            ctx.CreateAclEditor().BreakInheritance(Id("E32"), false).Apply();  // 0x20

            var aclE32 = CurrentContext.Security.GetAclInfo(Id("E32"));
            var aclE35 = ctx.GetAclInfo(Id("E35"));
            var aclE36 = ctx.GetAclInfo(Id("E36"));
            Assert.IsNotNull(aclE32);
            Assert.AreEqual(Id("E12"), aclE32.Parent.EntityId);
            //Assert.AreEqual(Id("E35"), aclE32.Children[0].EntityId);
            //Assert.AreEqual(Id("E36"), aclE32.Children[1].EntityId);
            Assert.AreEqual(Id("E32"), aclE35.Parent.EntityId);
            Assert.AreEqual(Id("E32"), aclE36.Parent.EntityId);

            Assert.AreEqual("-E32|", Tools.ReplaceIds(aclE32.ToString()));

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E32"));
            Assert.IsFalse(entity.IsInherited);

            Assert.AreEqual(Id("E36"), sec.GetSecurityEntity(Id("E37")).GetFirstAclId());
            Assert.AreEqual(Id("E36"), sec.GetSecurityEntity(Id("E36")).GetFirstAclId());
            Assert.AreEqual(Id("E32"), sec.GetSecurityEntity(Id("E32")).GetFirstAclId());
            Assert.AreEqual(Id("E12"), sec.GetSecurityEntity(Id("E30")).GetFirstAclId());
            Assert.AreEqual(Id("E12"), sec.GetSecurityEntity(Id("E12")).GetFirstAclId());
            Assert.AreEqual(Id("E1"), sec.GetSecurityEntity(Id("E4")).GetFirstAclId());
            Assert.AreEqual(Id("E1"), sec.GetSecurityEntity(Id("E1")).GetFirstAclId());

            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E32")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(0, aces.Length);

        }

        [TestMethod]
        public void AclEditor_BreakInheritance_Holder_WithoutCopy()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E4|+G2:+___________++_");
            SetAcl("+E12|+G2:______++++++___");
            SetAcl("+E33|+G2:_+++++_________");
            SetAcl("+E34|+G2:_+++++_________");

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E12"), false).Apply();

            var aclE12 = CurrentContext.Security.GetAclInfo(Id("E12"));
            var aclE33 = CurrentContext.Security.GetAclInfo(Id("E33"));
            var aclE34 = CurrentContext.Security.GetAclInfo(Id("E34"));
            Assert.IsNotNull(aclE12);
            Assert.AreEqual(Id("E4"), aclE12.Parent.EntityId);
            //Assert.AreEqual(Id("E33"), aclE12.Children[0].EntityId);
            //Assert.AreEqual(Id("E34"), aclE12.Children[1].EntityId);
            Assert.AreEqual(Id("E12"), aclE33.Parent.EntityId);
            Assert.AreEqual(Id("E12"), aclE34.Parent.EntityId);

            Assert.AreEqual("-E12|+G2:_______________________________________________________++++++___", Tools.ReplaceIds(aclE12.ToString()));

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E12"));
            Assert.IsFalse(entity.IsInherited);

            Assert.AreEqual(Id("E34"), sec.GetSecurityEntity(Id("E43")).GetFirstAclId());
            Assert.AreEqual(Id("E34"), sec.GetSecurityEntity(Id("E34")).GetFirstAclId());
            Assert.AreEqual(Id("E12"), sec.GetSecurityEntity(Id("E31")).GetFirstAclId());
            Assert.AreEqual(Id("E12"), sec.GetSecurityEntity(Id("E30")).GetFirstAclId());
            Assert.AreEqual(Id("E12"), sec.GetSecurityEntity(Id("E12")).GetFirstAclId());
            Assert.AreEqual(Id("E4"), sec.GetSecurityEntity(Id("E4")).GetFirstAclId());
            Assert.AreEqual(Id("E1"), sec.GetSecurityEntity(Id("E1")).GetFirstAclId());

            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E12")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(1, aces.Length);

        }
        [TestMethod]
        public void AclEditor_BreakInheritance_OnBreaked()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E4|+G2:+___________++_");
            SetAcl("+E12|+G2:______++++++___");
            SetAcl("+E33|+G2:_+++++_________");
            SetAcl("+E34|+G2:_+++++_________");

            // breaks, tests and repeat
            for (int i = 0; i < 3; i++)
            {
                CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E12"), false).Apply();

                var aclE12 = CurrentContext.Security.GetAclInfo(Id("E12"));
                var aclE4 = CurrentContext.Security.GetAclInfo(Id("E4"));
                var aclE33 = CurrentContext.Security.GetAclInfo(Id("E33"));
                var aclE34 = CurrentContext.Security.GetAclInfo(Id("E34"));
                Assert.IsNotNull(aclE12);
                Assert.AreEqual(Id("E4"), aclE12.Parent.EntityId);
                Assert.AreEqual(Id("E12"), aclE33.Parent.EntityId);
                Assert.AreEqual(Id("E12"), aclE34.Parent.EntityId);

                Assert.AreEqual("-E12|+G2:_______________________________________________________++++++___", Tools.ReplaceIds(aclE12.ToString()));

                var db = CurrentContext.Security.DataProvider;
                var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
                var sec = CurrentContext.Security;
                var entity = sec.GetSecurityEntity(Id("E12"));
                Assert.IsFalse(entity.IsInherited);

                Assert.AreEqual(Id("E34"), sec.GetSecurityEntity(Id("E43")).GetFirstAclId());
                Assert.AreEqual(Id("E34"), sec.GetSecurityEntity(Id("E34")).GetFirstAclId());
                Assert.AreEqual(Id("E12"), sec.GetSecurityEntity(Id("E31")).GetFirstAclId());
                Assert.AreEqual(Id("E12"), sec.GetSecurityEntity(Id("E30")).GetFirstAclId());
                Assert.AreEqual(Id("E12"), sec.GetSecurityEntity(Id("E12")).GetFirstAclId());
                Assert.AreEqual(Id("E4"), sec.GetSecurityEntity(Id("E4")).GetFirstAclId());
                Assert.AreEqual(Id("E1"), sec.GetSecurityEntity(Id("E1")).GetFirstAclId());

                var aceTable = dbAcc.Storage.Aces;
                var aces = aceTable.Where(x => x.EntityId == Id("E12")).OrderBy(x => x.IdentityId).ToArray();
                Assert.AreEqual(1, aces.Length);
            }
        }
        [TestMethod]
        public void AclEditor_UnbreakInheritance_WithNormalize()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");

            //#
            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E5")).Apply();

            Assert.AreEqual("-E5|+G1:_________________________________________________+++++++++++++++,+G2:_________________________________________________+-__________+++", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            //#
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E5"), Id("G2"), false, Tools.GetPermissionTypes("+++++++++++++++"))
                .Deny(Id("E5"), Id("G2"), false, Tools.GetPermissionTypes("_+_____________"))
                .Apply();

            Assert.AreEqual("-E5|+G1:_________________________________________________+++++++++++++++,+G2:_________________________________________________+-+++++++++++++", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            //#
            CurrentContext.Security.CreateAclEditor().UnbreakInheritance(Id("E5"), normalize: true).Apply();


            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E5"));
            Assert.IsTrue(entity.IsInherited);

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(1, aces.Length);
            Assert.AreEqual("E5|+G2:___________________________________________________++++++++++___", Tools.ReplaceIds(aces[0].ToString()));
        }
        [TestMethod]
        public void AclEditor_UnbreakInheritance_WithoutNormalize()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E5")).Apply();

            CurrentContext.Security.CreateAclEditor().UnbreakInheritance(Id("E5")).Apply();

            Assert.AreEqual("+E5|+G1:_________________________________________________+++++++++++++++,+G2:_________________________________________________+-__________+++", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E5"));
            Assert.IsTrue(entity.IsInherited);

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(2, aces.Length);
            Assert.AreEqual("E5|+G1:_________________________________________________+++++++++++++++", Tools.ReplaceIds(aces[0].ToString()));
            Assert.AreEqual("E5|+G2:_________________________________________________+-__________+++", Tools.ReplaceIds(aces[1].ToString()));
        }
        [TestMethod]
        public void AclEditor_UnbreakInheritance_OnUnbreaked()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");

            var sec = CurrentContext.Security;
            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var aceTable = dbAcc.Storage.Aces;

            Assert.AreEqual("+E2|+G2:_________________________________________________+___________++_", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E2")).ToString()));
            var entity = sec.GetSecurityEntity(Id("E2"));
            Assert.IsTrue(entity.IsInherited);
            var aces = aceTable.Where(x => x.EntityId == Id("E2")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(1, aces.Length);
            Assert.AreEqual("E2|+G2:_________________________________________________+___________++_", Tools.ReplaceIds(aces[0].ToString()));


            CurrentContext.Security.CreateAclEditor().UnbreakInheritance(Id("E2")).Apply();


            Assert.AreEqual("+E2|+G2:_________________________________________________+___________++_", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E2")).ToString()));
            entity = sec.GetSecurityEntity(Id("E2"));
            Assert.IsTrue(entity.IsInherited);
            aces = aceTable.Where(x => x.EntityId == Id("E2")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(1, aces.Length);
            Assert.AreEqual("E2|+G2:_________________________________________________+___________++_", Tools.ReplaceIds(aces[0].ToString()));
        }
        [TestMethod]
        public void AclEditor_UnbreakInheritance_WithNormalize_AcesAndHolderIds()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");

            var sec = CurrentContext.Security;
            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            
            var e2id = Id("E2");
            var e5id = Id("E5");

            Assert.AreEqual(e2id, sec.GetSecurityEntity(e5id).GetFirstAclId());

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E5")).Apply();

            Assert.AreEqual(e5id, sec.GetSecurityEntity(e5id).GetFirstAclId());

            CurrentContext.Security.CreateAclEditor().UnbreakInheritance(Id("E5"), normalize: true).Apply();

            Assert.AreEqual(e2id, sec.GetSecurityEntity(e5id).GetFirstAclId());

            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).ToArray();
            Assert.AreEqual(0, aces.Length);

            //Assert.IsNull(CurrentContext.Security.Cache.AclCache.Get(e5id));
            Assert.IsNull(CurrentContext.Security.GetAclInfo(e5id));
        }

        [TestMethod]
        public void AclEditor_NormalizeDoesNothing()
        {
            SetAcl("+E2|+G2:+___________++_");

            var ed = CurrentContext.Security.CreateAclEditor();

            ed.NormalizeExplicitePermissions(Id("E1"));
            ed.NormalizeExplicitePermissions(Id("E2"));
            ed.NormalizeExplicitePermissions(Id("E5"));
        }


        [TestMethod]
        public void AclEditor_CopyEffectivePermissions1()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");
            SetAcl("+E5|+G1:+___+++_____++_,+G2:___________++++");

            CurrentContext.Security.CreateAclEditor().CopyEffectivePermissions(Id("E5")).Apply();

            Assert.AreEqual("+E5|+G1:_________________________________________________+++++++++++++++,+G2:_________________________________________________+-_________++++", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(2, aces.Length);
            Assert.AreEqual("E5|+G1:_________________________________________________+++++++++++++++", Tools.ReplaceIds(aces[0].ToString()));
            Assert.AreEqual("E5|+G2:_________________________________________________+-_________++++", Tools.ReplaceIds(aces[1].ToString()));
        }
        [TestMethod]
        public void AclEditor_CopyEffectivePermissions2()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");
            SetAcl("+E5|+G1:+___+++_____++_,+G2:___________++++");

            CurrentContext.Security.CreateAclEditor().CopyEffectivePermissions(Id("E14")).Apply();

            Assert.AreEqual("+E14|+G1:_________________________________________________+++++++++++++++,+G2:_________________________________________________+-_________++++", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E14")).ToString()));

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E14")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(2, aces.Length);
            Assert.AreEqual("E14|+G1:_________________________________________________+++++++++++++++", Tools.ReplaceIds(aces[0].ToString()));
            Assert.AreEqual("E14|+G2:_________________________________________________+-_________++++", Tools.ReplaceIds(aces[1].ToString()));
        }
        [TestMethod]
        public void AclEditor_NormalizeExplicitePermissions1()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+-__________++_");
            SetAcl("+E5|+G1:+___+++_____++_,+G2:-__________++++");

            CurrentContext.Security.CreateAclEditor().NormalizeExplicitePermissions(Id("E5")).Apply();

            Assert.AreEqual("+E5|+G2:_________________________________________________-__________+___", Tools.ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(1, aces.Length);
            Assert.AreEqual("E5|+G2:_________________________________________________-__________+___", Tools.ReplaceIds(aces[0].ToString()));
        }       
        [TestMethod]
        public void AclEditor_NormalizeExplicitePermissions2()
        {
            SetAcl("+E1|+G1:+++++++++++++++,+G2:_-____________+");
            SetAcl("+E2|+G2:+___________++_");
            SetAcl("+E5|+G1:+___+++_____++_,+G2:___________++++");
            SetAcl("+E14|+G1:+++++++++++++++,+G2:+-_________++++");

            CurrentContext.Security.CreateAclEditor().NormalizeExplicitePermissions(Id("E14")).Apply();

            Assert.IsNull(CurrentContext.Security.GetAclInfo(Id("E14")));

            var db = CurrentContext.Security.DataProvider;
            var dbAcc = new MemoryDataProviderAccessor((MemoryDataProvider)db);
            var aceTable = dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E14")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(0, aces.Length);
        }
        #endregion


        [TestMethod]
        public void AclEditor_AllowDenyClear_Persistence()
        {
            var entity4Id = CurrentContext.Security.GetSecurityEntity(Id("E4")).Id;
            var user6Id = Id("U6");
            AclEditor ed;
            AccessControlList acl;

            //--------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            for (int i = 0; i < PermissionType.PermissionCount; i += 3)
                ed.Allow(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            for (int i = 1; i < PermissionType.PermissionCount; i += 3)
                ed.Deny(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            for (int i = 2; i < PermissionType.PermissionCount; i += 3)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            ed.Apply();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|+U6:+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+", Tools.ReplaceIds(acl.ToString()));

            //--------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            for (int i = 1; i < PermissionType.PermissionCount; i += 3)
                ed.Allow(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            for (int i = 2; i < PermissionType.PermissionCount; i += 3)
                ed.Deny(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            for (int i = 0; i < PermissionType.PermissionCount; i += 3)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            ed.Apply();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|+U6:_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_", Tools.ReplaceIds(acl.ToString()));

            //--------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            for (int i = 2; i < PermissionType.PermissionCount; i += 3)
                ed.Allow(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            for (int i = 0; i < PermissionType.PermissionCount; i += 3)
                ed.Deny(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            for (int i = 1; i < PermissionType.PermissionCount; i += 3)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            ed.Apply();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|+U6:-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-", Tools.ReplaceIds(acl.ToString()));

            //========================================================
            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionType.PermissionCount; i++)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            ed.Apply();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|", Tools.ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionType.PermissionCount; i++)
                ed.Allow(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            ed.Apply();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|+U6:++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++", Tools.ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionType.PermissionCount; i++)
                ed.Deny(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            ed.Apply();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|+U6:----------------------------------------------------------------", Tools.ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionType.PermissionCount; i++)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            ed.Apply();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|", Tools.ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionType.PermissionCount; i++)
                ed.Deny(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            ed.Apply();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|+U6:----------------------------------------------------------------", Tools.ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionType.PermissionCount; i++)
                ed.Allow(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            ed.Apply();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|+U6:++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++", Tools.ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionType.PermissionCount; i++)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionType.GetPermissionTypeByIndex(i));
            ed.Apply();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|", Tools.ReplaceIds(acl.ToString()));
        }



        [TestMethod]
        public void AccessControlList_NoExplicitEntry_ParentBreaked()
        {
            var ctx = CurrentContext.Security;

            ctx.CreateAclEditor().BreakInheritance(Id("E3"), false).Apply(); // with entry
            var acl3 = ctx.GetAcl(Id("E3"));
            var acl9 = ctx.GetAcl(Id("E9")); // child of E3 and no entry
            var acl25 = ctx.GetAcl(Id("E25")); // deeper descendant of E3 and no entry
            Assert.AreEqual(false, acl3.Inherits);
            Assert.AreEqual(true, acl9.Inherits);
            Assert.AreEqual(true, acl25.Inherits);

            ctx.CreateAclEditor().BreakInheritance(Id("E4"), false).Apply(); // without entry
            var acl4 = ctx.GetAcl(Id("E4"));
            var acl11 = ctx.GetAcl(Id("E11")); // child of E4 and no entry
            var acl34 = ctx.GetAcl(Id("E34")); // deeper descendant of E4 and no entry
            Assert.AreEqual(false, acl4.Inherits);
            Assert.AreEqual(true, acl11.Inherits);
            Assert.AreEqual(true, acl34.Inherits);
        }


        #region //======================================================================= Tools

        private Dictionary<int, TestEntity> _repository = new Dictionary<int, TestEntity>();

        private void EnsureRepository()
        {
            TestEntity e;
            var u1 = TestUser.User1;

            e = CreateEntity("E1", null, u1);
            {
                e = CreateEntity("E2", "E1", u1);
                {
                    e = CreateEntity("E5", "E2", u1);
                    {
                        e = CreateEntity("E14", "E5", u1);
                        {
                            e = CreateEntity("E50", "E14", u1);
                            {
                                e = CreateEntity("E51", "E50", u1);
                                {
                                    e = CreateEntity("E52", "E51", u1);
                                }
                                e = CreateEntity("E53", "E50", u1);
                            }
                        }
                        e = CreateEntity("E15", "E5", u1);
                    }
                    e = CreateEntity("E6", "E2", u1);
                    {
                        e = CreateEntity("E16", "E6", u1);
                        e = CreateEntity("E17", "E6", u1);
                    }
                    e = CreateEntity("E7", "E2", u1);
                    {
                        e = CreateEntity("E18", "E7", u1);
                        e = CreateEntity("E19", "E7", u1);
                    }
                }
                e = CreateEntity("E3", "E1", u1);
                {
                    e = CreateEntity("E8", "E3", u1);
                    {
                        e = CreateEntity("E20", "E8", u1);
                        e = CreateEntity("E21", "E8", u1);
                        {
                            e = CreateEntity("E22", "E21", u1);
                            e = CreateEntity("E23", "E21", u1);
                            e = CreateEntity("E24", "E21", u1);
                            e = CreateEntity("E25", "E21", u1);
                            e = CreateEntity("E26", "E21", u1);
                            e = CreateEntity("E27", "E21", u1);
                            e = CreateEntity("E28", "E21", u1);
                            e = CreateEntity("E29", "E21", u1);
                        }
                    }
                    e = CreateEntity("E9", "E3", u1);
                    e = CreateEntity("E10", "E3", u1);
                }
               e = CreateEntity("E4", "E1", u1);
               {
                   e = CreateEntity("E11", "E4", u1);
                   e = CreateEntity("E12", "E4", u1);
                   {
                       e = CreateEntity("E30", "E12", u1);
                       {
                           e = CreateEntity("E31", "E30", u1);
                           {
                               e = CreateEntity("E33", "E31", u1);
                               e = CreateEntity("E34", "E31", u1);
                               {
                                   e = CreateEntity("E40", "E34", u1);
                                   e = CreateEntity("E43", "E34", u1);
                                   {
                                       e = CreateEntity("E44", "E43", u1);
                                       e = CreateEntity("E45", "E43", u1);
                                       e = CreateEntity("E46", "E43", u1);
                                       e = CreateEntity("E47", "E43", u1);
                                       e = CreateEntity("E48", "E43", u1);
                                       e = CreateEntity("E49", "E43", u1);
                                   }
                               }
                           }
                           e = CreateEntity("E32", "E30", u1);
                           {
                               e = CreateEntity("E35", "E32", u1);
                               {
                                   e = CreateEntity("E41", "E35", u1);
                                   {
                                       e = CreateEntity("E42", "E41", u1);
                                   }
                               }
                               e = CreateEntity("E36", "E32", u1);
                               {
                                   e = CreateEntity("E37", "E36", u1);
                                   {
                                       e = CreateEntity("E38", "E37", u1);
                                       e = CreateEntity("E39", "E37", u1);
                                   }
                               }
                           }
                       }
                   }
                   e = CreateEntity("E13", "E4", u1);
               }
            }
        }


        private int Id(string name)
        {
            return Tools.GetId(name);
        }

        private void SetAcl(string src)
        {
            Tools.SetAcl(CurrentContext.Security, src);
        }

        private void SetAclForEverything(int loadedLevel)
        {
            for (int i = 0; i < CurrentContext.Security.Cache.Entities.Count; i++)
                SetAcl(String.Format("+E{0}|+U1:+++++++++++++++", i + 1));
        }

        private AceInfo CreateAce(string src)
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
                IdentityId = Id(a[0]),
                AllowBits = allowBits,
                DenyBits = denyBits
            };
        }

        private TestEntity CreateEntity(string name, string parentName, TestUser owner)
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
            return entity;
        }
        private TestEntity GetRepositoryEntity(int id)
        {
            return _repository[id];
        }

        #endregion
    }
}
