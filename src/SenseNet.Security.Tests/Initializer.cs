using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;
using System.Configuration;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class Initializer
    {
        [AssemblyInitialize]
        public static void InitializeAllTests(TestContext context)
        {
            var _ = PermissionType.See; // pre-loads the type
        }
    }
}
