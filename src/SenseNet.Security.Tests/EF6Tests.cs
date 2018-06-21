using System.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.EF6SecurityStore;

namespace SenseNet.Security.Tests
{
    // ReSharper disable once InconsistentNaming
    [TestClass]
    public class EF6Tests : TestCases
    {
        protected override ISecurityDataProvider GetDataProvider()
        {
            return new EF6SecurityDataProvider(connectionString:
                ConfigurationManager.ConnectionStrings["EF6SecurityStorage"].ConnectionString);
        }

        protected override void CleanupMemberships()
        {
            var providerAcc = new PrivateObject((EF6SecurityDataProvider)CurrentContext.Security.DataProvider);
            var db = (SecurityStorage)providerAcc.Invoke("Db");
            db.Database.ExecuteSqlCommand("DELETE FROM [EFMemberships]");
        }


        [TestMethod]
        public void Xxy()
        {
            Assert.Inconclusive();
        }

    }
}
