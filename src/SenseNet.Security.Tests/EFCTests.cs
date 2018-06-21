using System.Configuration;
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
    }
}
