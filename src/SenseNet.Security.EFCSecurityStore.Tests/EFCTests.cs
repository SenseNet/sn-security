using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Extensions.DependencyInjection;
using SenseNet.Security.Tests;

namespace SenseNet.Security.EFCSecurityStore.Tests
{
    // ReSharper disable once InconsistentNaming
    [TestClass]
    public class EFCTests : TestCases
    {
        protected override ISecurityDataProvider GetDataProvider()
        {
            return new EFCSecurityDataProvider(0, Configuration.Instance.GetConnectionString());
        }

        protected override void CleanupMemberships()
        {
            //var providerAcc = new PrivateObject((EFCSecurityDataProvider) CurrentContext.Security.DataProvider);
            //var db = (SecurityStorage)providerAcc.Invoke("Db");
            //db.Database.ExecuteSqlCommand("DELETE FROM [EFMemberships]");

            var dp = CurrentContext.Security.GetDataProvider();
            foreach (var group in dp.LoadAllGroups())
            {
                dp.RemoveMembers(group.Id, group.UserMemberIds, group.Groups.Select(g => g.Id));
            }
        }

        [TestMethod]
        public void EFC_Services_Register()
        {
            // part 1 ----------------------------------------------------------
            var services = new ServiceCollection()
                .AddLogging();

            // WITHOUT configuration
            services.AddEFCSecurityDataProvider();

            var provider = services.BuildServiceProvider();
            var sdp = provider.GetRequiredService<ISecurityDataProvider>();

            Assert.IsTrue(sdp is EFCSecurityDataProvider);
            Assert.AreEqual(null, sdp.ConnectionString);

            // part 2 ----------------------------------------------------------
            services = new ServiceCollection()
                .AddLogging();

            // WITH configuration
            services.AddEFCSecurityDataProvider(options =>
            {
                options.ConnectionString = "test123";
                options.SqlCommandTimeout = 123;
            });

            provider = services.BuildServiceProvider();
            sdp = provider.GetRequiredService<ISecurityDataProvider>();

            Assert.IsTrue(sdp is EFCSecurityDataProvider);
            Assert.AreEqual("test123", sdp.ConnectionString);
        }
    }
}
