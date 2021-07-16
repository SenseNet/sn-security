using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;
using Microsoft.Extensions.Configuration;
using SenseNet.Security.Messaging;

namespace SenseNet.Security.EFCSecurityStore.Tests
{
    [TestClass]
    public class Initializer
    {
        [AssemblyInitialize]
        public static void InitializeAllTests(TestContext context)
        {
            Configuration.Instance = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build();

            // install db directly
            new EFCSecurityDataProvider(new MessageSenderManager(), 0, Configuration.Instance.GetConnectionString())
                .InstallDatabase();

            var _ = PermissionType.See; // pre-loads the type
        }
    }
}
