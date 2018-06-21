using Microsoft.VisualStudio.TestTools.UnitTesting;
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
    }
}
