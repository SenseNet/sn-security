using System.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.EFCSecurityStore;

namespace SenseNet.Security.Tests
{
    // ReSharper disable once InconsistentNaming
    [TestClass]
    public class EFCTests : TestCases
    {
        protected override ISecurityDataProvider GetDataProvider()
        {
            return new EFCSecurityDataProvider(connectionString:
                ConfigurationManager.ConnectionStrings["EFCSecurityStorage"].ConnectionString);
        }

        protected override void CleanupMemberships()
        {
            var providerAcc = new PrivateObject((EFCSecurityDataProvider) CurrentContext.Security.DataProvider);
            var db = (SecurityStorage)providerAcc.Invoke("Db");
            db.Database.ExecuteSqlCommand("DELETE FROM [EFMemberships]");
        }

    }
}
