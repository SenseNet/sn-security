using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Data;
using SenseNet.Security.Tests.TestPortal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class EntityDictionaryTests : TestCases
    {
        protected override ISecurityDataProvider GetDataProvider()
        {
            MemoryDataProvider.LastActivityId = 0;
            return new MemoryDataProvider(DatabaseStorage.CreateEmpty());
        }

        protected override void CleanupMemberships()
        {
            MemoryDataProvider.Storage.Memberships.Clear();
        }


        [TestMethod]
        public void EntityDict_Indexer_Existing()
        {
            var ids = "1,2,4,5,7,8,9".Split(',').Select(x => "E" + x).ToArray();
            var context = CurrentContext.Security;
            var ownerId = TestUser.User1.Id;
            foreach (var id in ids)
                context.CreateSecurityEntity(Id(id), 0, ownerId);

            Assert.AreEqual(Id("E1"), context.Cache.Entities[Id("E1")].Id);
            Assert.AreEqual(Id("E2"), context.Cache.Entities[Id("E2")].Id);
            Assert.AreEqual(Id("E4"), context.Cache.Entities[Id("E4")].Id);
            Assert.AreEqual(Id("E5"), context.Cache.Entities[Id("E5")].Id);
            Assert.AreEqual(Id("E7"), context.Cache.Entities[Id("E7")].Id);
            Assert.AreEqual(Id("E8"), context.Cache.Entities[Id("E8")].Id);
            Assert.AreEqual(Id("E9"), context.Cache.Entities[Id("E9")].Id);
        }
        [TestMethod]
        public void EntityDict_Indexer_Missing()
        {
            var ids = "1,2,4,5,7,8,9".Split(',').Select(x => "E" + x).ToArray();
            var context = CurrentContext.Security;
            var ownerId = TestUser.User1.Id;
            foreach (var id in ids)
                context.CreateSecurityEntity(Id(id), 0, ownerId);

            var missingIds = new[] { -1, 0, Id("E3"), Id("E6"), Id("E10"), Id("E11") };
            foreach (var id in missingIds)
            {
                try
                {
                    var x = context.Cache.Entities[id];
                    Assert.Fail("Expected exception was not thrown. Id: " + id);
                }
                catch (KeyNotFoundException)
                {
                    // do nothing
                }
            }
        }
        [TestMethod]
        public void EntityDict_TryGet()
        {
            var ids = new[] { 1, 2, 4, 5, 7, 8, 9 };

            var context = CurrentContext.Security;
            var ownerId = TestUser.User1.Id;
            foreach (var id in ids)
                context.CreateSecurityEntity(id, 0, ownerId);
            
            Assert.IsFalse(context.Cache.Entities.TryGetValue(-1, out _));
            Assert.IsFalse(context.Cache.Entities.TryGetValue(0, out _));
            Assert.IsTrue(context.Cache.Entities.TryGetValue(1, out _));
            Assert.IsTrue(context.Cache.Entities.TryGetValue(2, out _));
            Assert.IsFalse(context.Cache.Entities.TryGetValue(3, out _));
            Assert.IsTrue(context.Cache.Entities.TryGetValue(4, out _));
            Assert.IsTrue(context.Cache.Entities.TryGetValue(5, out _));
            Assert.IsFalse(context.Cache.Entities.TryGetValue(6, out _));
            Assert.IsTrue(context.Cache.Entities.TryGetValue(7, out _));
            Assert.IsTrue(context.Cache.Entities.TryGetValue(8, out _));
            Assert.IsTrue(context.Cache.Entities.TryGetValue(9, out _));
            Assert.IsFalse(context.Cache.Entities.TryGetValue(10, out _));
            Assert.IsFalse(context.Cache.Entities.TryGetValue(11, out _));
        }


    }
}
