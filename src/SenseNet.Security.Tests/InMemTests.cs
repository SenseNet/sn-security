using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Extensions.DependencyInjection;
using SenseNet.Security.Data;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class InMemTests : TestCases
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
        public void InMem_Services_Register()
        {
            var services = new ServiceCollection()
                .AddLogging();

            services.AddInMemorySecurityDataProvider(new DatabaseStorage
            {
                Entities = new Dictionary<int, StoredSecurityEntity>
                {
                    { 123, new StoredSecurityEntity { Id = 123 } }
                }
            });

            var provider = services.BuildServiceProvider();
            var sdp = (MemoryDataProvider)provider.GetRequiredService<ISecurityDataProvider>();
            
            Assert.AreEqual(123, sdp.LoadSecurityEntities().Single().Id);
        }
    }
}
