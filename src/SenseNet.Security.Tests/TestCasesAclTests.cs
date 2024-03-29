﻿using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;
// ReSharper disable JoinDeclarationAndInitializer
// ReSharper disable StringLiteralTypo

namespace SenseNet.Security.Tests
{
    public abstract partial class TestCases
    {
        [TestMethod]
        public void Acl_Get0()
        {
            EnsureRepository();

            var acl = CurrentContext.Security.GetAclInfo(int.MaxValue);
            Assert.IsNull(acl);
        }
        [TestMethod]
        public void Acl_Get1()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:______________+");
            var acl = CurrentContext.Security.GetAcl(Id("E3"));
            Assert.AreEqual("+E3|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:_______________________________________________________________+", ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Acl_Get2()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");

            var acl = CurrentContext.Security.GetAcl(Id("E2"));
            Assert.AreEqual("+E2|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:_________________________________________________+-__________+++", ReplaceIds(acl.ToString()));

            acl = CurrentContext.Security.GetAcl(Id("E3"));
            Assert.AreEqual("+E3|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:__________________________________________________-____________+", ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Acl_Get3()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");
            SetAcl("+E3|Normal|+G3:+-+-+-+-+-+-+-+");

            var acl = CurrentContext.Security.GetAcl(Id("E3"));
            Assert.AreEqual("+E3|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:__________________________________________________-____________+,Normal|+G3:_________________________________________________+-+-+-+-+-+-+-+", ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Acl_Get4()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");
            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E3"), new EntryType[0])
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            SetAcl("-E3|Normal|-G3:+-+-+-+-+-+-+-+");

            var acl = CurrentContext.Security.GetAcl(Id("E3"));

            Assert.AreEqual("-E3|Normal|-G3:_________________________________________________+-+-+-+-+-+-+-+", ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Acl_Get_BrokenEmpty()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");
            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E3"), new EntryType[0])
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var acl = CurrentContext.Security.GetAcl(Id("E3"));

            Assert.AreEqual("-E3|", ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void Acl_Get_WithMembership()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1");
            Assert.IsTrue(CurrentContext.Security.SecuritySystem.Cache.IsInGroup(Id("U1"), Id("G1")), "G1 not contains U1");
            Assert.IsFalse(CurrentContext.Security.SecuritySystem.Cache.IsInGroup(int.MaxValue, int.MaxValue - 1), "Any group contains anyone");
            SetAcl("+E1|Normal|+U1:________---_+++,Normal|+G1:---_+++________");
            var acl = CurrentContext.Security.GetAcl(Id("E1"));
            Assert.AreEqual("+E1|Normal|+G1:_________________________________________________---_+++________,Normal|+U1:_________________________________________________________---_+++", ReplaceIds(acl.ToString()));

            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("______________+")));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("_____________+_")));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("____________+__")));

            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("___________+___")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("__________+____")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("_________+_____")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("________+______")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("_______+_______")));

            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("______+________")));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("_____+_________")));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("____+__________")));

            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("___+___________")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("__+____________")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("_+_____________")));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), GetPermissionTypes("+______________")));
        }

        [TestMethod]
        public void Eval_HasPermission_Allow()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|Normal|+G1:______________+,Normal|+G2:_____________+_");
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.See, PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See, PermissionType.Preview));
            foreach (var perm in PermissionTypeBase.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), perm),
                        $"{perm.Name} permission on E1 is true, expected: false.");
                    Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E2"), perm),
                        $"{perm.Name} permission on E2 is true, expected: false.");
                }
            }
        }
        [TestMethod]
        public void Eval_HasPermission_Deny()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:-------------++,Normal|+G3:+-+-+-+-+-+-+-+,Normal|-G4:+-+-+-+-+-+-+-+");
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E1"), PermissionType.See, PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See, PermissionType.Preview));
            foreach (var perm in PermissionTypeBase.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E1"), perm),
                        $"{perm.Name} permission on E1 is true, expected: false.");
                    Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E2"), perm),
                        $"{perm.Name} permission on E2 is true, expected: false.");
                }
            }
        }
        [TestMethod]
        public void Eval_AssertPermission()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|Normal|+G1:______________+,Normal|+G2:_____________+_");
            CurrentContext.Security.AssertPermission(Id("E1"), PermissionType.See);
            CurrentContext.Security.AssertPermission(Id("E1"), PermissionType.Preview);
            CurrentContext.Security.AssertPermission(Id("E1"), PermissionType.See, PermissionType.Preview);
            CurrentContext.Security.AssertPermission(Id("E2"), PermissionType.See);
            CurrentContext.Security.AssertPermission(Id("E2"), PermissionType.Preview);
            CurrentContext.Security.AssertPermission(Id("E2"), PermissionType.See, PermissionType.Preview);
            foreach (var perm in PermissionTypeBase.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    try
                    {
                        CurrentContext.Security.AssertPermission(Id("E1"), perm);
                        Assert.Fail($"{perm.Name} permission on E1 is true, expected: false.");
                    }
                    catch (AccessDeniedException) { }
                    try
                    {
                        CurrentContext.Security.AssertPermission(Id("E2"), perm);
                        Assert.Fail($"{perm.Name} permission on E2 is true, expected: false.");
                    }
                    catch (AccessDeniedException) { }
                }
            }
        }
        [TestMethod]
        public void Eval_AssertPermission3()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|Normal|+G1:______________+,Normal|+G2:_____________+_");

            var e1 = GetRepositoryEntity(Id("E1"));
            var e2 = GetRepositoryEntity(Id("E2"));

            CurrentContext.Security.AssertPermission(e1.Id, PermissionType.See);
            CurrentContext.Security.AssertPermission(e1.Id, PermissionType.Preview);
            CurrentContext.Security.AssertPermission(e1.Id, PermissionType.See, PermissionType.Preview);
            CurrentContext.Security.AssertPermission(e2.Id, PermissionType.See);
            CurrentContext.Security.AssertPermission(e2.Id, PermissionType.Preview);
            CurrentContext.Security.AssertPermission(e2.Id, PermissionType.See, PermissionType.Preview);
            foreach (var perm in PermissionTypeBase.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    try
                    {
                        CurrentContext.Security.AssertPermission(e1.Id, perm);
                        Assert.Fail($"{perm.Name} permission on E1 is true, expected: false.");
                    }
                    catch (AccessDeniedException) { }
                    try
                    {
                        CurrentContext.Security.AssertPermission(e2.Id, perm);
                        Assert.Fail($"{perm.Name} permission on E2 is true, expected: false.");
                    }
                    catch (AccessDeniedException) { }
                }
            }
        }
        [TestMethod]
        public void Eval_HasPermission_Break()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|Normal|+G1:______________+");
            SetAcl("-E2|Normal|+G1:_____________+_");
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.Preview));
            Assert.IsFalse(CurrentContext.Security.HasPermission(Id("E2"), PermissionType.See, PermissionType.Preview));
        }
        [TestMethod]
        public void Eval_HasPermission_LocalOnly()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|Normal|+G1:______________+");
            SetAcl("+E2|Normal|-G1:_____________+_");
            SetAcl("+E5|Normal|+G1:____________+__");

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
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|Normal|+G1:______________+,Normal|+G2:_____________+_");
            SetAcl("+E3|Normal|+G1:_____________+_,Normal|+G2:______________+");
            SetAcl("+E9|Normal|+G3:___________+__+,Normal|+G4:_______+_____+_");
            SetAcl("+E20|Normal|+G3:_+___________+_,Normal|+G4:____+_________+");

            Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.See));
            Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.Preview));
            Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.See, PermissionType.Preview));

            foreach (var perm in PermissionTypeBase.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    Assert.IsFalse(CurrentContext.Security.HasSubtreePermission(Id("E1"), perm),
                        $"{perm.Name} subtree permission on E1 is true, expected: false.");
                    Assert.IsFalse(CurrentContext.Security.HasSubtreePermission(Id("E3"), perm),
                        $"{perm.Name} subtree permission on E3 is true, expected: false.");
                }
            }


            SetAcl("+E21|Normal|+G2:_____________-_,Normal|+G3:_+___________+_,Normal|+G4:____+________-+");

            //Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.Open));
            Assert.IsFalse(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.Preview));
            Assert.IsFalse(CurrentContext.Security.HasSubtreePermission(Id("E3"), PermissionType.See, PermissionType.Preview));
        }
        [TestMethod]
        public void Eval_HasSubtreePermission_EmptySubTree_BugReproduction()
        {
            EnsureRepository();

            //E9 is an empty subtree (leaf) and has inherited permissions
            SetMembership(CurrentContext.Security, "U1:G1");
            CurrentContext.Security.CreateAclEditor()
                .Allow(Id("E1"), Id("G1"), false, PermissionType.See)
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.IsTrue(CurrentContext.Security.HasSubtreePermission(Id("E9"), PermissionType.See));
        }
        [TestMethod]
        public async Task Eval_AssertSubtreePermission()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|Normal|+G1:______________+,Normal|+G2:_____________+_");
            SetAcl("+E3|Normal|+G1:_____________+_,Normal|+G2:______________+");
            SetAcl("+E9|Normal|+G3:___________+__+,Normal|+G4:_______+_____+_");
            SetAcl("+E20|Normal|+G3:_+___________+_,Normal|+G4:____+_________+");

            var origOwnerId = Id("U1");
            const int differentOwnerId = int.MaxValue;
            var cancel = CancellationToken.None;

            CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.See);
            CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.Preview);
            await CurrentContext.Security.ModifyEntityOwnerAsync(Id("E3"), differentOwnerId, cancel)
                .ConfigureAwait(false);
            try
            {
                CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.See, PermissionType.Preview);
            }
            finally
            {
                await CurrentContext.Security.ModifyEntityOwnerAsync(Id("E3"), origOwnerId, cancel)
                    .ConfigureAwait(false);
            }

            foreach (var perm in PermissionTypeBase.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    try
                    {
                        CurrentContext.Security.AssertSubtreePermission(Id("E1"), perm);
                        Assert.Fail($"{perm.Name} subtree permission on E1 is true, expected: false.");
                    }
                    catch
                    {
                        // ignored
                    }
                    try
                    {
                        await CurrentContext.Security.ModifyEntityOwnerAsync(Id("E3"), differentOwnerId, cancel)
                            .ConfigureAwait(false);
                        CurrentContext.Security.AssertSubtreePermission(Id("E3"), perm);
                        Assert.Fail($"{perm.Name} subtree permission on E3 is true, expected: false.");
                    }
                    catch
                    {
                        // ignored
                    }
                    finally
                    {
                        await CurrentContext.Security.ModifyEntityOwnerAsync(Id("E3"), origOwnerId, cancel)
                            .ConfigureAwait(false);
                    }
                }
            }


            SetAcl("+E21|Normal|+G2:_____________-_,Normal|+G3:_+___________+_,Normal|+G4:____+________-+");

            try
            {
                CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.Preview);
                Assert.Fail("Edit subtree permission on E3 is true, expected: false.");
            }
            catch
            {
                // ignored
            }
            try
            {
                await CurrentContext.Security.ModifyEntityOwnerAsync(Id("E3"), differentOwnerId, cancel)
                    .ConfigureAwait(false);
                CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.See, PermissionType.Preview);
                Assert.Fail("Open+Edit subtree permission on E3 is true, expected: false.");
            }
            catch
            {
                // ignored
            }
            finally
            {
                await CurrentContext.Security.ModifyEntityOwnerAsync(Id("E3"), origOwnerId, cancel)
                    .ConfigureAwait(false);
            }
        }
        [TestMethod]
        public async Task Eval_AssertSubtreePermission_Entity()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|Normal|+G1:______________+,Normal|+G2:_____________+_");
            SetAcl("+E3|Normal|+G1:_____________+_,Normal|+G2:______________+");
            SetAcl("+E9|Normal|+G3:___________+__+,Normal|+G4:_______+_____+_");
            SetAcl("+E20|Normal|+G3:_+___________+_,Normal|+G4:____+_________+");

            var origOwnerId = Id("U1");
            const int differentOwnerId = int.MaxValue;

            var e1 = GetRepositoryEntity(Id("E1"));
            var e3 = GetRepositoryEntity(Id("E3"));

            CurrentContext.Security.AssertSubtreePermission(e3.Id, PermissionType.See);
            CurrentContext.Security.AssertSubtreePermission(e3.Id, PermissionType.Preview);
            CurrentContext.Security.AssertSubtreePermission(e3.Id, PermissionType.See, PermissionType.Preview);

            foreach (var perm in PermissionTypeBase.GetPermissionTypes())
            {
                if (perm != PermissionType.See && perm != PermissionType.Preview)
                {
                    try
                    {
                        CurrentContext.Security.AssertSubtreePermission(e1.Id, perm);
                        Assert.Fail($"{perm.Name} subtree permission on E1 is true, expected: false.");
                    }
                    catch
                    {
                        // ignored
                    }
                    try
                    {
                        CurrentContext.Security.AssertSubtreePermission(e3.Id, perm);
                        Assert.Fail($"{perm.Name} subtree permission on E3 is true, expected: false.");
                    }
                    catch
                    {
                        // ignored
                    }
                }
            }


            SetAcl("+E21|Normal|+G2:_____________-_,Normal|+G3:_+___________+_,Normal|+G4:____+________-+");

            try
            {
                CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.Preview);
                Assert.Fail("Edit subtree permission on E3 is true, expected: false.");
            }
            catch
            {
                // ignored
            }
            try
            {
                await CurrentContext.Security.ModifyEntityOwnerAsync(Id("E3"), differentOwnerId, CancellationToken.None)
                    .ConfigureAwait(false);
                CurrentContext.Security.AssertSubtreePermission(Id("E3"), PermissionType.See, PermissionType.Preview);
                Assert.Fail("Open+Edit subtree permission on E3 is true, expected: false.");
            }
            catch
            {
                // ignored
            }
            finally
            {
                await CurrentContext.Security.ModifyEntityOwnerAsync(Id("E3"), origOwnerId, CancellationToken.None)
                    .ConfigureAwait(false);
            }
        }
        [TestMethod]
        public void Eval_GetSubtreePermission_BreakAllowLocalOnly()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1,G2|U2:G1");
            SetAcl("+E1|Normal|+G1:______________+,Normal|+G2:_____________+_");
            SetAcl("+E3|Normal|+G1:_____________+_,Normal|+G2:______________+");
            SetAcl("+E8|Normal|+G1:__________+++++,Normal|+U1:_________++++++");
            SetAcl("+E20|Normal|+G3:_+___________+_,Normal|+G4:____+_________+");
            SetAcl("-E21|Normal|+G1:__________+++++,Normal|-U1:_________++++++"); // on a node
            SetAcl("-E29|Normal|+G1:__________+++++,Normal|-U1:_________++++++"); // on a leaf

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
            EnsureRepository();

            SetAcl("-E21|Normal|+G1:__________+++++,Normal|-G2:_________++++++");

            // E26 node is a child of E21 and it should not inherit its parent's local only entries
            Assert.AreEqual("+E26|Normal|+G1:___________________________________________________________+++++",
                ReplaceIds(CurrentContext.Security.GetAcl(Id("E26")).ToString()));
        }

        [TestMethod]
        public void Eval_EffectivePermissions()
        {
            EnsureRepository();

            AclEditor ed;
            var _ = CurrentContext.Security.SecuritySystem.DataProvider;

            var u1 = Id("U1");
            var u2 = Id("U2");
            var g1 = Id("G1");

            ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E1"), u1, false, GetPermissionTypes("_____________pp"));
            ed.Deny(Id("E1"), u1, false, GetPermissionTypes("____________p__"));
            ed.Allow(Id("E1"), u2, false, GetPermissionTypes("__________pp_pp"));
            ed.Deny(Id("E1"), u2, false, GetPermissionTypes("_________p__p__"));
            ed.Allow(Id("E2"), u1, false, GetPermissionTypes("__________pp___"));
            ed.Deny(Id("E2"), u1, false, GetPermissionTypes("_________p_____"));
            ed.Allow(Id("E2"), g1, false, GetPermissionTypes("__________pp_pp"));
            ed.Deny(Id("E2"), g1, false, GetPermissionTypes("_________p__p__"));
            ed.Allow(Id("E5"), u1, false, GetPermissionTypes("_______pp______"));
            ed.Deny(Id("E5"), u1, false, GetPermissionTypes("______p________"));
            ed.Allow(Id("E5"), u2, false, GetPermissionTypes("____pp_pp______"));
            ed.Deny(Id("E5"), u2, false, GetPermissionTypes("___p__p________"));
            ed.Allow(Id("E5"), g1, false, GetPermissionTypes("_pp_pp_pp______"));
            ed.Deny(Id("E5"), g1, false, GetPermissionTypes("p__p__p________"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var entries = CurrentContext.Security.GetEffectiveEntries(Id("E5"))
                .OrderBy(e => e.IdentityId).ToList();

            Assert.AreEqual(3, entries.Count);
            Assert.AreEqual("Normal|+G1:_________________________________________________-++-++-++-++-++", ReplaceIds(entries[0].ToString()));
            Assert.AreEqual("Normal|+U1:_______________________________________________________-++-++-++", ReplaceIds(entries[1].ToString()));
            Assert.AreEqual("Normal|+U2:____________________________________________________-++-++-++-++", ReplaceIds(entries[2].ToString()));
        }

        [TestMethod]
        public void AclEditor_PermissionBitMask1()
        {
            EnsureRepository();

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
        [SuppressMessage("ReSharper", "RedundantAssignment")]
        [SuppressMessage("ReSharper", "NotAccessedVariable")]
        public void AclEditor_CreationPossibilities()
        {
            EnsureRepository();

            AclEditor ed;
            
            ed = new AclEditor(CurrentContext.Security);
            ed = CurrentContext.Security.CreateAclEditor();
        }
        [TestMethod]
        public void AclEditor_AllowDenyClear()
        {
            EnsureRepository();

            var entity = CurrentContext.Security.GetSecurityEntity(Id("E1"));
            var ed = CurrentContext.Security.CreateAclEditor();
            var acls = new AclEditorAccessor(ed).Acls;
            var userId = Id("U1");
            var ace = new AceInfo { IdentityId = userId };
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
            EnsureRepository();

            var entityId = CurrentContext.Security.GetSecurityEntity(Id("E1")).Id;
            var userId1 = Id("U1");
            var userId2 = Id("U2");

            var ed = CurrentContext.Security.CreateAclEditor();
            var acls = new AclEditorAccessor(ed).Acls;

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

            var ace1 = aces.FirstOrDefault(x => x.IdentityId == userId1 && x.LocalOnly == false);
            var ace2 = aces.FirstOrDefault(x => x.IdentityId == userId2 && x.LocalOnly == false);
            var ace3 = aces.FirstOrDefault(x => x.IdentityId == userId1 && x.LocalOnly);
            var ace4 = aces.FirstOrDefault(x => x.IdentityId == userId2 && x.LocalOnly);

            Assert.AreEqual(userId1, ace1?.IdentityId);
            Assert.AreEqual(false, ace1?.LocalOnly);
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask | PermissionType.PreviewWithoutWatermark.Mask, ace1?.AllowBits);
            Assert.AreEqual(PermissionType.Publish.Mask | PermissionType.Delete.Mask, ace1?.DenyBits);

            Assert.AreEqual(userId2, ace2?.IdentityId);
            Assert.AreEqual(false, ace2?.LocalOnly);
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask | PermissionType.PreviewWithoutWatermark.Mask, ace2?.AllowBits);
            Assert.AreEqual(PermissionType.Publish.Mask | PermissionType.Delete.Mask, ace2?.DenyBits);

            Assert.AreEqual(userId1, ace3?.IdentityId);
            Assert.AreEqual(true, ace3?.LocalOnly);
            Assert.AreEqual(PermissionType.PreviewWithoutRedaction.Mask | PermissionType.Open.Mask, ace3?.AllowBits);
            Assert.AreEqual(PermissionType.DeleteOldVersion.Mask | PermissionType.RecallOldVersion.Mask, ace3?.DenyBits);

            Assert.AreEqual(userId2, ace4?.IdentityId);
            Assert.AreEqual(true, ace4?.LocalOnly);
            Assert.AreEqual(PermissionType.PreviewWithoutRedaction.Mask | PermissionType.Open.Mask, ace4?.AllowBits);
            Assert.AreEqual(PermissionType.DeleteOldVersion.Mask | PermissionType.RecallOldVersion.Mask, ace4?.DenyBits);
        }
        [TestMethod]
        public void AclEditor_AllowDenyAll()
        {
            EnsureRepository();

            CurrentContext.Security.CreateAclEditor().Set(Id("E1"), Id("U1"), false, new PermissionBitMask { AllowBits = ~0ul, DenyBits = 0ul })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("+E1|Normal|+U1:++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E1")).ToString()));

            CurrentContext.Security.CreateAclEditor().Set(Id("E1"), Id("U1"), false, new PermissionBitMask { AllowBits = 0ul, DenyBits = ~0ul })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("+E1|Normal|+U1:----------------------------------------------------------------", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E1")).ToString()));
        }
        [TestMethod]
        public void AclEditor_SetMoreBits()
        {
            EnsureRepository();

            var entityId = CurrentContext.Security.GetSecurityEntity(Id("E1")).Id;
            var userId1 = Id("U1");
            var userId2 = Id("U2");

            var ed = CurrentContext.Security.CreateAclEditor();
            var acls = new AclEditorAccessor(ed).Acls;

            //#
            ed.Set(entityId, userId1, false, PermissionType.See | PermissionType.Preview | PermissionType.PreviewWithoutWatermark | ~PermissionType.Publish | ~PermissionType.Delete);
            ed.Set(entityId, userId2, false, PermissionType.See | PermissionType.Preview | PermissionType.PreviewWithoutWatermark | ~PermissionType.Publish | ~PermissionType.Delete);
            ed.Set(entityId, userId1, true, PermissionType.PreviewWithoutRedaction | PermissionType.Open | ~PermissionType.DeleteOldVersion | ~PermissionType.RecallOldVersion);
            ed.Set(entityId, userId2, true, PermissionType.PreviewWithoutRedaction | PermissionType.Open | ~PermissionType.DeleteOldVersion | ~PermissionType.RecallOldVersion);

            var acl = acls[entityId];
            var aces = acl.Entries;

            Assert.AreEqual(4, aces.Count);

            var ace1 = aces.FirstOrDefault(x => x.IdentityId == userId1 && x.LocalOnly == false);
            var ace2 = aces.FirstOrDefault(x => x.IdentityId == userId2 && x.LocalOnly == false);
            var ace3 = aces.FirstOrDefault(x => x.IdentityId == userId1 && x.LocalOnly);
            var ace4 = aces.FirstOrDefault(x => x.IdentityId == userId2 && x.LocalOnly);

            Assert.AreEqual(userId1, ace1?.IdentityId);
            Assert.AreEqual(false, ace1?.LocalOnly);
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask | PermissionType.PreviewWithoutWatermark.Mask, ace1?.AllowBits);
            Assert.AreEqual(PermissionType.Publish.Mask | PermissionType.Delete.Mask, ace1?.DenyBits);

            Assert.AreEqual(userId2, ace2?.IdentityId);
            Assert.AreEqual(false, ace2?.LocalOnly);
            Assert.AreEqual(PermissionType.See.Mask | PermissionType.Preview.Mask | PermissionType.PreviewWithoutWatermark.Mask, ace2?.AllowBits);
            Assert.AreEqual(PermissionType.Publish.Mask | PermissionType.Delete.Mask, ace2?.DenyBits);

            Assert.AreEqual(userId1, ace3?.IdentityId);
            Assert.AreEqual(true, ace3?.LocalOnly);
            Assert.AreEqual(PermissionType.PreviewWithoutRedaction.Mask | PermissionType.Open.Mask, ace3?.AllowBits);
            Assert.AreEqual(PermissionType.DeleteOldVersion.Mask | PermissionType.RecallOldVersion.Mask, ace3?.DenyBits);

            Assert.AreEqual(userId2, ace4?.IdentityId);
            Assert.AreEqual(true, ace4?.LocalOnly);
            Assert.AreEqual(PermissionType.PreviewWithoutRedaction.Mask | PermissionType.Open.Mask, ace4?.AllowBits);
            Assert.AreEqual(PermissionType.DeleteOldVersion.Mask | PermissionType.RecallOldVersion.Mask, ace4?.DenyBits);
        }
        [TestMethod]
        public void AclEditor_AllowMoreEntriesInOneEditor()
        {
            EnsureRepository();

            var entityId1 = CurrentContext.Security.GetSecurityEntity(Id("E1")).Id;
            var entityId2 = CurrentContext.Security.GetSecurityEntity(Id("E2")).Id;
            var userId1 = Id("U1");
            var userId2 = Id("U2");

            var ed = CurrentContext.Security.CreateAclEditor();

            ed.Allow(entityId1, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark);
            ed.Allow(entityId1, userId2, false, PermissionType.See);
            ed.Allow(entityId2, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark, PermissionType.PreviewWithoutRedaction);
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var acl = CurrentContext.Security.GetAcl(entityId2);
            Assert.AreEqual("+E2|Normal|+U1:____________________________________________________________++++,Normal|+U2:_______________________________________________________________+", ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void AclEditor_RemovePermissions()
        {
            EnsureRepository();

            var entityId1 = CurrentContext.Security.GetSecurityEntity(Id("E1")).Id;
            var entityId2 = CurrentContext.Security.GetSecurityEntity(Id("E2")).Id;
            var userId1 = Id("U1");
            var userId2 = Id("U2");

            var ed = CurrentContext.Security.CreateAclEditor();

            ed.Allow(entityId1, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark);
            ed.Allow(entityId1, userId2, false, PermissionType.See);
            ed.Allow(entityId2, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark, PermissionType.PreviewWithoutRedaction);
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var acl = CurrentContext.Security.GetAcl(entityId2);
            Assert.AreEqual("+E2|Normal|+U1:____________________________________________________________++++,Normal|+U2:_______________________________________________________________+", ReplaceIds(acl.ToString()));

            //#
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(entityId2, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark, PermissionType.PreviewWithoutRedaction);
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            acl = CurrentContext.Security.GetAcl(entityId2);
            Assert.AreEqual("+E2|Normal|+U1:_____________________________________________________________+++,Normal|+U2:_______________________________________________________________+", ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void AclEditor_ResetPermissions()
        {
            EnsureRepository();

            var entityId1 = CurrentContext.Security.GetSecurityEntity(Id("E1")).Id;
            var entityId2 = CurrentContext.Security.GetSecurityEntity(Id("E2")).Id;
            var userId1 = Id("U1");
            var userId2 = Id("U2");

            var ed = CurrentContext.Security.CreateAclEditor();

            ed.Allow(entityId1, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark);
            ed.Allow(entityId1, userId2, false, PermissionType.See);
            ed.Allow(entityId2, userId1, false, PermissionType.See, PermissionType.Preview, PermissionType.PreviewWithoutWatermark, PermissionType.PreviewWithoutRedaction);
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var acl = CurrentContext.Security.GetAcl(entityId2);
            Assert.AreEqual("+E2|Normal|+U1:____________________________________________________________++++,Normal|+U2:_______________________________________________________________+", ReplaceIds(acl.ToString()));

            //#
            ed = CurrentContext.Security.CreateAclEditor();
            ed.Reset(entityId2, userId1, false, PermissionType.See | PermissionType.Preview | PermissionType.PreviewWithoutWatermark | PermissionType.PreviewWithoutRedaction);
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            acl = CurrentContext.Security.GetAcl(entityId2);
            Assert.AreEqual("+E2|Normal|+U1:_____________________________________________________________+++,Normal|+U2:_______________________________________________________________+", ReplaceIds(acl.ToString()));
        }
        [TestMethod]
        public void AclEditor_KeepInheritedPermissions()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1");

            var uid1 = Id("U1");
            var gid1 = Id("G1");

            var ed0 = CurrentContext.Security.CreateAclEditor();
            ed0.Allow(Id("E1"), Id("U1"), false, GetPermissionTypes("______________p"));
            ed0.Allow(Id("E2"), Id("U1"), false, GetPermissionTypes("_____________p_"));
            ed0.Allow(Id("E5"), Id("U1"), false, GetPermissionTypes("____________p__"));
            ed0.Allow(Id("E14"), Id("U1"), false, GetPermissionTypes("___________p___"));
            ed0.Allow(Id("E50"), Id("U1"), false, GetPermissionTypes("__________p____"));
            ed0.Allow(Id("E51"), Id("U1"), false, GetPermissionTypes("_________p_____"));
            ed0.Allow(Id("E1"), Id("G1"), false, GetPermissionTypes("______p________"));
            ed0.Allow(Id("E2"), Id("G1"), false, GetPermissionTypes("_____p_________"));
            ed0.Allow(Id("E5"), Id("G1"), false, GetPermissionTypes("____p__________"));
            ed0.Allow(Id("E14"), Id("G1"), false, GetPermissionTypes("___p___________"));
            ed0.Allow(Id("E50"), Id("G1"), false, GetPermissionTypes("__p____________"));
            ed0.Allow(Id("E51"), Id("G1"), false, GetPermissionTypes("_p_____________"));
            ed0.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("__________________________________________________++++++__++++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# set some new and more irrelevant permissions
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.Deny(Id("E52"), uid1, false, GetPermissionTypes("________ppppppp"));
            ed.Deny(Id("E52"), gid1, false, GetPermissionTypes("ppppppp________"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("_________________________________________________-------_-------", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E52"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E52"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("__________________________________________________++++++__++++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E51"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E51"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("___________________________________________________+++++___+++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E50"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E50"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("____________________________________________________++++____++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E1"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E1"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("____________________________________________________+++_____+++_", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E2"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E2"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("____________________________________________________++______++__", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E5"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E5"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("____________________________________________________+_______+___", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E14"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E14"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("________________________________________________________________", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));
        }
        [TestMethod]
        public void AclEditor_KeepInheritedPermissions_CommonAclEditor()
        {
            EnsureRepository();

            SetMembership(CurrentContext.Security, "U1:G1");

            var uid1 = Id("U1");
            var gid1 = Id("G1");

            var ed0 = CurrentContext.Security.CreateAclEditor();
            ed0.Allow(Id("E1"), Id("U1"), false, GetPermissionTypes("______________p"));
            ed0.Allow(Id("E2"), Id("U1"), false, GetPermissionTypes("_____________p_"));
            ed0.Allow(Id("E5"), Id("U1"), false, GetPermissionTypes("____________p__"));
            ed0.Allow(Id("E14"), Id("U1"), false, GetPermissionTypes("___________p___"));
            ed0.Allow(Id("E50"), Id("U1"), false, GetPermissionTypes("__________p____"));
            ed0.Allow(Id("E51"), Id("U1"), false, GetPermissionTypes("_________p_____"));
            ed0.Allow(Id("E1"), Id("G1"), false, GetPermissionTypes("______p________"));
            ed0.Allow(Id("E2"), Id("G1"), false, GetPermissionTypes("_____p_________"));
            ed0.Allow(Id("E5"), Id("G1"), false, GetPermissionTypes("____p__________"));
            ed0.Allow(Id("E14"), Id("G1"), false, GetPermissionTypes("___p___________"));
            ed0.Allow(Id("E50"), Id("G1"), false, GetPermissionTypes("__p____________"));
            ed0.Allow(Id("E51"), Id("G1"), false, GetPermissionTypes("_p_____________"));
            ed0.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("__________________________________________________++++++__++++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# set some new and more irrelevant permissions
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.Deny(Id("E52"), uid1, false, GetPermissionTypes("________ppppppp"));
            ed.Deny(Id("E52"), gid1, false, GetPermissionTypes("ppppppp________"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("_________________________________________________-------_-------", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E52"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E52"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("__________________________________________________++++++__++++++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E51"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E51"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E50"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E50"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E1"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E1"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E2"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E2"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E5"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E5"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("____________________________________________________+_______+___", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));
            Assert.AreEqual(default, CurrentContext.Security.SecuritySystem.Cache.Entities[Id("E5")].GetFirstAclId());

            //# clear all permissions (inherited won't be cleared)
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E14"), uid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ClearPermission(Id("E14"), gid1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert.AreEqual("________________________________________________________________", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), Id("U1"), default));
        }
        [TestMethod]
        public void AclEditor_EmptyEntriesRemovedFromDatabase()
        {
            EnsureRepository();

            var u1 = Id("U1");

            var ed0 = CurrentContext.Security.CreateAclEditor();
            ed0.Allow(Id("E1"), u1, false, GetPermissionTypes("________p_p_p_p"));
            ed0.Deny(Id("E1"), u1, false, GetPermissionTypes("_______p_p_p_p_"));
            ed0.Allow(Id("E2"), u1, false, GetPermissionTypes("p_p_p_p________"));
            ed0.Deny(Id("E2"), u1, false, GetPermissionTypes("_p_p_p_________"));
            ed0.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var db = CurrentContext.Security.SecuritySystem.DataProvider;

            Assert.AreEqual("_________________________________________________+-+-+-+-+-+-+-+", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E5"), u1, default));
            var dbEntries1 = db.LoadPermissionEntriesAsync(new[] { Id("E1") }, CancellationToken.None)
                .GetAwaiter().GetResult().ToArray();
            var dbEntries2 = db.LoadPermissionEntriesAsync(new[] { Id("E2") }, CancellationToken.None)
                .GetAwaiter().GetResult().ToArray();
            Assert.AreEqual(1, dbEntries1.Length);
            Assert.AreEqual(1, dbEntries2.Length);

            //# clear all permissions (inherited won't be cleared)
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E2"), u1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual("________________________________________________________-+-+-+-+", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E52"), u1, default));
            dbEntries1 = db.LoadPermissionEntriesAsync(new[] { Id("E1") }, CancellationToken.None)
                .GetAwaiter().GetResult().ToArray();
            dbEntries2 = db.LoadPermissionEntriesAsync(new[] { Id("E2") }, CancellationToken.None)
                .GetAwaiter().GetResult().ToArray();
            Assert.AreEqual(1, dbEntries1.Length);
            Assert.AreEqual(0, dbEntries2.Length);
        }
        [TestMethod]
        public void AclEditor_EmptyEntriesRemovedFromMemory()
        {
            EnsureRepository();

            var u1 = Id("U1");

            var ed0 = CurrentContext.Security.CreateAclEditor();
            ed0.Allow(Id("E1"), u1, false, GetPermissionTypes("________p_p_p_p"));
            ed0.Deny(Id("E1"), u1, false, GetPermissionTypes("_______p_p_p_p_"));
            ed0.Allow(Id("E2"), u1, false, GetPermissionTypes("p_p_p_p________"));
            ed0.Deny(Id("E2"), u1, false, GetPermissionTypes("_p_p_p_________"));
            ed0.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var acl1 = CurrentContext.Security.GetAclInfo(Id("E1"));
            var acl2 = CurrentContext.Security.GetAclInfo(Id("E2"));
            Assert.AreEqual(1, acl1.Entries.Count);
            Assert.AreEqual(1, acl2.Entries.Count);

            //# clear all permissions (inherited won't be cleared)
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E2"), u1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            acl1 = CurrentContext.Security.GetAclInfo(Id("E1"));
            acl2 = CurrentContext.Security.GetAclInfo(Id("E2"));
            Assert.AreEqual(1, acl1.Entries.Count);
            Assert.IsNull(acl2);
        }
        [TestMethod]
        public void AclEditor_BrokenEmptyAclIsNotDeletedFromMemory()
        {
            EnsureRepository();

            var u1 = Id("U1");

            var ed0 = CurrentContext.Security.CreateAclEditor();
            ed0.Allow(Id("E1"), u1, false, GetPermissionTypes("________p_p_p_p"));
            ed0.Deny(Id("E1"), u1, false, GetPermissionTypes("_______p_p_p_p_"));
            ed0.Allow(Id("E2"), u1, false, GetPermissionTypes("p_p_p_p________"));
            ed0.Deny(Id("E2"), u1, false, GetPermissionTypes("_p_p_p_________"));
            ed0.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var acl1 = CurrentContext.Security.GetAclInfo(Id("E1"));
            var acl2 = CurrentContext.Security.GetAclInfo(Id("E2"));
            Assert.AreEqual(1, acl1.Entries.Count);
            Assert.AreEqual(1, acl2.Entries.Count);

            //# clear all permissions (inherited won't be cleared)
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.BreakInheritance(Id("E2"), new[] { EntryType.Normal });

            ed.ClearPermission(Id("E2"), u1, false, GetPermissionTypes("ppppppppppppppp"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            acl1 = CurrentContext.Security.GetAclInfo(Id("E1"));
            acl2 = CurrentContext.Security.GetAclInfo(Id("E2"));
            Assert.AreEqual(1, acl1.Entries.Count);
            Assert.AreEqual(0, acl2.Entries.Count);
            Assert.AreEqual(false, acl2.Inherits);
        }

        [TestMethod]
        public void AclEditor_UseLocalOnlyValues()
        {
            EnsureRepository();

            var u1 = Id("U1");

            var ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E1"), u1, false, GetPermissionTypes("______________p"));
            ed.Allow(Id("E2"), u1, true, GetPermissionTypes("_____________p_"));
            ed.Allow(Id("E5"), u1, false, GetPermissionTypes("____________p__"));
            ed.Allow(Id("E14"), u1, false, GetPermissionTypes("___________p___"));
            ed.Deny(Id("E1"), u1, false, GetPermissionTypes("______p________"));
            ed.Deny(Id("E2"), u1, false, GetPermissionTypes("_____p_________"));
            ed.Deny(Id("E5"), u1, true, GetPermissionTypes("____p__________"));
            ed.Deny(Id("E14"), u1, false, GetPermissionTypes("___p___________"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual("_______________________________________________________-_______+", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E1"), u1, default));
            Assert.AreEqual("______________________________________________________--______++", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E2"), u1, default));
            Assert.AreEqual("_____________________________________________________---_____+_+", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E5"), u1, default));
            Assert.AreEqual("____________________________________________________-_--____++_+", CurrentContext.Security.Evaluator._traceEffectivePermissionValues(Id("E14"), u1, default));
        }
        [TestMethod]
        public void AclEditor_NearestHolderId()
        {
            EnsureRepository();

            AclEditor ed;
            var sec = CurrentContext.Security;

            var u1 = Id("U1");
            const int eid0 = default;
            var eid1 = Id("E1");
            var eid2 = Id("E2");
            var eid3 = Id("E3");
            var eid5 = Id("E5");
            var eid14 = Id("E14");
            var eid15 = Id("E15");
            var eid17 = Id("E17");

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E2"), u1, false, GetPermissionTypes("_____________P_"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid17).GetFirstAclId());

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E1"), u1, false, GetPermissionTypes("______________p"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual(eid1, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid1, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid17).GetFirstAclId());

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E5"), u1, false, GetPermissionTypes("____________P__"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual(eid1, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid1, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid17).GetFirstAclId());

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E1"), u1, false, GetPermissionTypes("______________P"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid5, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid17).GetFirstAclId());

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E5"), u1, false, GetPermissionTypes("____________P__"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid1).GetFirstAclId());
            Assert.AreEqual(eid0, sec.GetSecurityEntity(eid3).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid2).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid5).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid14).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid15).GetFirstAclId());
            Assert.AreEqual(eid2, sec.GetSecurityEntity(eid17).GetFirstAclId());

            //--------------------------------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            ed.ClearPermission(Id("E2"), u1, false, GetPermissionTypes("_____________P_"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

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
            EnsureRepository();

            AclEditor ed;

            var u1 = Id("U1");

            ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E1"), u1, false, GetPermissionTypes("____________ppp"));
            ed.Allow(Id("E2"), u1, false, GetPermissionTypes("_________ppp___"));
            ed.Allow(Id("E5"), u1, false, GetPermissionTypes("______ppp______"));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var acl = CurrentContext.Security.GetAcl(Id("E1"));
            Assert.AreEqual(64, acl.Entries.First().Permissions.Count(x => x.AllowFrom == default && x.DenyFrom == default));

            acl = CurrentContext.Security.GetAcl(Id("E2"));
            Assert.AreEqual(61, acl.Entries.First().Permissions.Count(x => x.AllowFrom == default && x.DenyFrom == default));

            acl = CurrentContext.Security.GetAcl(Id("E5"));
            Assert.AreEqual(58, acl.Entries.First().Permissions.Count(x => x.AllowFrom == default && x.DenyFrom == default));

            acl = CurrentContext.Security.GetAcl(Id("E14"));
            Assert.AreEqual(55, acl.Entries.First().Permissions.Count(x => x.AllowFrom == default && x.DenyFrom == default));
        }


        [TestMethod]
        public void AclEditor_Break_NotHolder_WithCopy()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E5"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual("-E5|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:_________________________________________________+-__________+++", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E5"));
            Assert.IsFalse(entity.IsInherited);

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
            var aceTable = db.LoadAllAces(); // dbAcc.Storage.Aces;
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(2, aces.Length);
            Assert.AreEqual("E5|Normal|+G1:_________________________________________________+++++++++++++++", ReplaceIds(aces[0].ToString()));
            Assert.AreEqual("E5|Normal|+G2:_________________________________________________+-__________+++", ReplaceIds(aces[1].ToString()));
        }
        [TestMethod]
        public void AclEditor_Break_Holder_WithCopy()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E2"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var aclInfo = CurrentContext.Security.GetAclInfo(Id("E2"));
            Assert.IsNotNull(aclInfo);
            Assert.AreEqual("-E2|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:_________________________________________________+-__________+++", ReplaceIds(aclInfo.ToString()));

            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E2"));
            Assert.IsFalse(entity.IsInherited);

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E2")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(2, aces.Length);
            Assert.AreEqual("E2|Normal|+G1:_________________________________________________+++++++++++++++", ReplaceIds(aces[0].ToString()));
            Assert.AreEqual("E2|Normal|+G2:_________________________________________________+-__________+++", ReplaceIds(aces[1].ToString()));
        }
        [TestMethod]
        public void AclEditor_Break_NotHolder_WithoutCopy()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E5"), new EntryType[0])
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var aclInfo = CurrentContext.Security.GetAclInfo(Id("E5"));
            Assert.IsNotNull(aclInfo);
            Assert.AreEqual("-E5|", ReplaceIds(aclInfo.ToString()));

            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E5"));
            Assert.IsFalse(entity.IsInherited);

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(0, aces.Length);
        }
        [TestMethod]
        public void AclEditor_Break_NotHolder_WithoutCopy_ChildrenAcls()
        {
            EnsureRepository();

            //Break on E32
            //Expected:
            //  children ACLs: E35, E36
            //  not children ACLs: E33, E34

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");       // 0x01        // 0x01
            SetAcl("+E12|Normal|+G2:+___________++_");                                 //   0x0C      //   0x0C
            SetAcl("+E33|Normal|+G2:_+++++++++++___");                                 //     0x21    //     0x21
            SetAcl("+E34|Normal|+G2:_+++++++++++___");                                 //     0x22    //     0x22
            SetAcl("+E35|Normal|+G2:_+++++++++++___");                                 //     0x23    //     0x20  0x23
            SetAcl("+E36|Normal|+G2:_+++++++++++___");                                 //     0x24    //           0x24

            var ctx = CurrentContext.Security;
            ctx.CreateAclEditor().BreakInheritance(Id("E32"), new EntryType[0])
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();  // 0x20

            var aclE32 = CurrentContext.Security.GetAclInfo(Id("E32"));
            var aclE35 = ctx.GetAclInfo(Id("E35"));
            var aclE36 = ctx.GetAclInfo(Id("E36"));
            Assert.IsNotNull(aclE32);
            Assert.AreEqual(Id("E12"), aclE32.Parent.EntityId);
            //Assert.AreEqual(Id("E35"), aclE32.Children[0].EntityId);
            //Assert.AreEqual(Id("E36"), aclE32.Children[1].EntityId);
            Assert.AreEqual(Id("E32"), aclE35.Parent.EntityId);
            Assert.AreEqual(Id("E32"), aclE36.Parent.EntityId);

            Assert.AreEqual("-E32|", ReplaceIds(aclE32.ToString()));

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
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

            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E32")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(0, aces.Length);

        }

        [TestMethod]
        public void AclEditor_Break_Holder_WithoutCopy()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E4|Normal|+G2:+___________++_");
            SetAcl("+E12|Normal|+G2:______++++++___");
            SetAcl("+E33|Normal|+G2:_+++++_________");
            SetAcl("+E34|Normal|+G2:_+++++_________");

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E12"), new EntryType[0])
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            var aclE12 = CurrentContext.Security.GetAclInfo(Id("E12"));
            var aclE33 = CurrentContext.Security.GetAclInfo(Id("E33"));
            var aclE34 = CurrentContext.Security.GetAclInfo(Id("E34"));
            Assert.IsNotNull(aclE12);
            Assert.AreEqual(Id("E4"), aclE12.Parent.EntityId);
            //Assert.AreEqual(Id("E33"), aclE12.Children[0].EntityId);
            //Assert.AreEqual(Id("E34"), aclE12.Children[1].EntityId);
            Assert.AreEqual(Id("E12"), aclE33.Parent.EntityId);
            Assert.AreEqual(Id("E12"), aclE34.Parent.EntityId);

            Assert.AreEqual("-E12|Normal|+G2:_______________________________________________________++++++___", ReplaceIds(aclE12.ToString()));

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
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

            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E12")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(1, aces.Length);

        }
        [TestMethod]
        public void AclEditor_Break_OnBroken()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E4|Normal|+G2:+___________++_");
            SetAcl("+E12|Normal|+G2:______++++++___");
            SetAcl("+E33|Normal|+G2:_+++++_________");
            SetAcl("+E34|Normal|+G2:_+++++_________");

            // breaks, tests and repeat
            for (var i = 0; i < 3; i++)
            {
                CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E12"), new EntryType[0])
                    .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

                var aclE12 = CurrentContext.Security.GetAclInfo(Id("E12"));
                //var aclE4 = CurrentContext.Security.GetAclInfo(Id("E4"));
                var aclE33 = CurrentContext.Security.GetAclInfo(Id("E33"));
                var aclE34 = CurrentContext.Security.GetAclInfo(Id("E34"));
                Assert.IsNotNull(aclE12);
                Assert.AreEqual(Id("E4"), aclE12.Parent.EntityId);
                Assert.AreEqual(Id("E12"), aclE33.Parent.EntityId);
                Assert.AreEqual(Id("E12"), aclE34.Parent.EntityId);

                Assert.AreEqual("-E12|Normal|+G2:_______________________________________________________++++++___", ReplaceIds(aclE12.ToString()));

                var db = CurrentContext.Security.SecuritySystem.DataProvider;
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

                var aceTable = db.LoadAllAces();
                var aces = aceTable.Where(x => x.EntityId == Id("E12")).OrderBy(x => x.IdentityId).ToArray();
                Assert.AreEqual(1, aces.Length);
            }
        }
        [TestMethod]
        public void AclEditor_UndoBreak_WithNormalize()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");

            //#
            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E5"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual("-E5|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:_________________________________________________+-__________+++", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            //#
            var ed = CurrentContext.Security.CreateAclEditor();
            ed.Allow(Id("E5"), Id("G2"), false, GetPermissionTypes("+++++++++++++++"))
                .Deny(Id("E5"), Id("G2"), false, GetPermissionTypes("_+_____________"))
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual("-E5|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:_________________________________________________+-+++++++++++++", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            //#
            CurrentContext.Security.CreateAclEditor().UnBreakInheritance(Id("E5"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();


            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E5"));
            Assert.IsTrue(entity.IsInherited);

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(1, aces.Length);
            Assert.AreEqual("E5|Normal|+G2:___________________________________________________++++++++++___", ReplaceIds(aces[0].ToString()));
        }
        [TestMethod]
        public void AclEditor_UndoBreak_WithoutNormalize()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E5"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            CurrentContext.Security.CreateAclEditor().UnBreakInheritance(Id("E5"), new EntryType[0])
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual("+E5|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:_________________________________________________+-__________+++", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            var sec = CurrentContext.Security;
            var entity = sec.GetSecurityEntity(Id("E5"));
            Assert.IsTrue(entity.IsInherited);

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(2, aces.Length);
            Assert.AreEqual("E5|Normal|+G1:_________________________________________________+++++++++++++++", ReplaceIds(aces[0].ToString()));
            Assert.AreEqual("E5|Normal|+G2:_________________________________________________+-__________+++", ReplaceIds(aces[1].ToString()));
        }
        [TestMethod]
        public void AclEditor_UndoBreak_OnUndoneBreak()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");

            var sec = CurrentContext.Security;
            var db = CurrentContext.Security.SecuritySystem.DataProvider;
            var aceTable = db.LoadAllAces().ToArray();

            Assert.AreEqual("+E2|Normal|+G2:_________________________________________________+___________++_", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E2")).ToString()));
            var entity = sec.GetSecurityEntity(Id("E2"));
            Assert.IsTrue(entity.IsInherited);
            var aces = aceTable.Where(x => x.EntityId == Id("E2")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(1, aces.Length);
            Assert.AreEqual("E2|Normal|+G2:_________________________________________________+___________++_", ReplaceIds(aces[0].ToString()));


            CurrentContext.Security.CreateAclEditor().UnBreakInheritance(Id("E2"), new EntryType[0])
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();


            Assert.AreEqual("+E2|Normal|+G2:_________________________________________________+___________++_", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E2")).ToString()));
            entity = sec.GetSecurityEntity(Id("E2"));
            Assert.IsTrue(entity.IsInherited);
            aces = aceTable.Where(x => x.EntityId == Id("E2")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(1, aces.Length);
            Assert.AreEqual("E2|Normal|+G2:_________________________________________________+___________++_", ReplaceIds(aces[0].ToString()));
        }
        [TestMethod]
        public void AclEditor_UndoBreak_WithNormalize_AcesAndHolderIds()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");

            var sec = CurrentContext.Security;
            var db = CurrentContext.Security.SecuritySystem.DataProvider;

            var e2Id = Id("E2");
            var e5Id = Id("E5");

            Assert.AreEqual(e2Id, sec.GetSecurityEntity(e5Id).GetFirstAclId());

            CurrentContext.Security.CreateAclEditor().BreakInheritance(Id("E5"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual(e5Id, sec.GetSecurityEntity(e5Id).GetFirstAclId());

            CurrentContext.Security.CreateAclEditor().UnBreakInheritance(Id("E5"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual(e2Id, sec.GetSecurityEntity(e5Id).GetFirstAclId());

            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).ToArray();
            Assert.AreEqual(0, aces.Length);

            //Assert.IsNull(CurrentContext.Security.Cache.AclCache.Get(e5id));
            Assert.IsNull(CurrentContext.Security.GetAclInfo(e5Id));
        }

        [TestMethod]
        public void AclEditor_NormalizeDoesNothing()
        {
            EnsureRepository();

            SetAcl("+E2|Normal|+G2:+___________++_");

            var ed = CurrentContext.Security.CreateAclEditor();

            ed.NormalizeExplicitPermissions(Id("E1"), new[] { EntryType.Normal });
            ed.NormalizeExplicitPermissions(Id("E2"), new[] { EntryType.Normal });
            ed.NormalizeExplicitPermissions(Id("E5"), new[] { EntryType.Normal });
        }


        [TestMethod]
        public void AclEditor_CopyEffectivePermissions1()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");
            SetAcl("+E5|Normal|+G1:+___+++_____++_,Normal|+G2:___________++++");

            CurrentContext.Security.CreateAclEditor().CopyEffectivePermissions(Id("E5"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual("+E5|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:_________________________________________________+-_________++++", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(2, aces.Length);
            Assert.AreEqual("E5|Normal|+G1:_________________________________________________+++++++++++++++", ReplaceIds(aces[0].ToString()));
            Assert.AreEqual("E5|Normal|+G2:_________________________________________________+-_________++++", ReplaceIds(aces[1].ToString()));
        }
        [TestMethod]
        public void AclEditor_CopyEffectivePermissions2()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");
            SetAcl("+E5|Normal|+G1:+___+++_____++_,Normal|+G2:___________++++");

            CurrentContext.Security.CreateAclEditor().CopyEffectivePermissions(Id("E14"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual("+E14|Normal|+G1:_________________________________________________+++++++++++++++,Normal|+G2:_________________________________________________+-_________++++", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E14")).ToString()));

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E14")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(2, aces.Length);
            Assert.AreEqual("E14|Normal|+G1:_________________________________________________+++++++++++++++", ReplaceIds(aces[0].ToString()));
            Assert.AreEqual("E14|Normal|+G2:_________________________________________________+-_________++++", ReplaceIds(aces[1].ToString()));
        }
        [TestMethod]
        public void AclEditor_NormalizeExplicitPermissions1()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+-__________++_");
            SetAcl("+E5|Normal|+G1:+___+++_____++_,Normal|+G2:-__________++++");

            CurrentContext.Security.CreateAclEditor().NormalizeExplicitPermissions(Id("E5"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.AreEqual("+E5|Normal|+G2:_________________________________________________-__________+___", ReplaceIds(CurrentContext.Security.GetAclInfo(Id("E5")).ToString()));

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E5")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(1, aces.Length);
            Assert.AreEqual("E5|Normal|+G2:_________________________________________________-__________+___", ReplaceIds(aces[0].ToString()));
        }
        [TestMethod]
        public void AclEditor_NormalizeExplicitPermissions2()
        {
            EnsureRepository();

            SetAcl("+E1|Normal|+G1:+++++++++++++++,Normal|+G2:_-____________+");
            SetAcl("+E2|Normal|+G2:+___________++_");
            SetAcl("+E5|Normal|+G1:+___+++_____++_,Normal|+G2:___________++++");
            SetAcl("+E14|Normal|+G1:+++++++++++++++,Normal|+G2:+-_________++++");

            CurrentContext.Security.CreateAclEditor().NormalizeExplicitPermissions(Id("E14"), new[] { EntryType.Normal })
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.IsNull(CurrentContext.Security.GetAclInfo(Id("E14")));

            var db = CurrentContext.Security.SecuritySystem.DataProvider;
            var aceTable = db.LoadAllAces();
            var aces = aceTable.Where(x => x.EntityId == Id("E14")).OrderBy(x => x.IdentityId).ToArray();
            Assert.AreEqual(0, aces.Length);
        }


        [TestMethod]
        public void AclEditor_AllowDenyClear_Persistence()
        {
            EnsureRepository();

            var entity4Id = CurrentContext.Security.GetSecurityEntity(Id("E4")).Id;
            var user6Id = Id("U6");
            AclEditor ed;
            AccessControlList acl;

            //--------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i += 3)
                ed.Allow(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            for (var i = 1; i < PermissionTypeBase.PermissionCount; i += 3)
                ed.Deny(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            for (var i = 2; i < PermissionTypeBase.PermissionCount; i += 3)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|Normal|+U6:+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+", ReplaceIds(acl.ToString()));

            //--------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 1; i < PermissionTypeBase.PermissionCount; i += 3)
                ed.Allow(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            for (var i = 2; i < PermissionTypeBase.PermissionCount; i += 3)
                ed.Deny(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i += 3)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|Normal|+U6:_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_", ReplaceIds(acl.ToString()));

            //--------------------------------------------------------
            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 2; i < PermissionTypeBase.PermissionCount; i += 3)
                ed.Allow(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i += 3)
                ed.Deny(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            for (var i = 1; i < PermissionTypeBase.PermissionCount; i += 3)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|Normal|+U6:-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-+_-", ReplaceIds(acl.ToString()));

            //========================================================
            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|", ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                ed.Allow(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|Normal|+U6:++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++", ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                ed.Deny(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|Normal|+U6:----------------------------------------------------------------", ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|", ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                ed.Deny(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|Normal|+U6:----------------------------------------------------------------", ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                ed.Allow(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|Normal|+U6:++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++", ReplaceIds(acl.ToString()));

            ed = CurrentContext.Security.CreateAclEditor();
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
                ed.ClearPermission(entity4Id, user6Id, false, PermissionTypeBase.GetPermissionTypeByIndex(i));
            ed.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
            acl = CurrentContext.Security.GetAcl(entity4Id);
            Assert.AreEqual("+E4|", ReplaceIds(acl.ToString()));
        }


        [TestMethod]
        public void AccessControlList_NoExplicitEntry_ParentBroken()
        {
            EnsureRepository();

            var ctx = CurrentContext.Security;

            ctx.CreateAclEditor().BreakInheritance(Id("E3"), new EntryType[0])
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult(); // with entry
            var acl3 = ctx.GetAcl(Id("E3"));
            var acl9 = ctx.GetAcl(Id("E9")); // child of E3 and no entry
            var acl25 = ctx.GetAcl(Id("E25")); // deeper descendant of E3 and no entry
            Assert.AreEqual(false, acl3.Inherits);
            Assert.AreEqual(true, acl9.Inherits);
            Assert.AreEqual(true, acl25.Inherits);

            ctx.CreateAclEditor().BreakInheritance(Id("E4"), new EntryType[0])
                .ApplyAsync(CancellationToken.None).GetAwaiter().GetResult(); // without entry
            var acl4 = ctx.GetAcl(Id("E4"));
            var acl11 = ctx.GetAcl(Id("E11")); // child of E4 and no entry
            var acl34 = ctx.GetAcl(Id("E34")); // deeper descendant of E4 and no entry
            Assert.AreEqual(false, acl4.Inherits);
            Assert.AreEqual(true, acl11.Inherits);
            Assert.AreEqual(true, acl34.Inherits);
        }
    }
}
