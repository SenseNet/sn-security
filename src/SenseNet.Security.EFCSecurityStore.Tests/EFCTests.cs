using System.Configuration;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests;

namespace SenseNet.Security.EFCSecurityStore.Tests
{
    // ReSharper disable once InconsistentNaming
    [TestClass]
    public class EFCTests : TestCases
    {
        protected override ISecurityDataProvider GetDataProvider()
        {
            return new EFCSecurityDataProvider(connectionString: Configuration.Instance.GetConnectionString());
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
    }
}
