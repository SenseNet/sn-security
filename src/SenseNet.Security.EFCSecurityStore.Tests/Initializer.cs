using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SenseNet.Security.EFCSecurityStore.Configuration;
using SenseNet.Security.Tests;
using SenseNet.Tools;

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
            new EFCSecurityDataProvider(
                    DiTools.CreateMessageSenderManager(),
                    new DefaultRetrier(Options.Create(new RetrierOptions()), NullLogger<DefaultRetrier>.Instance),
                    Options.Create(new DataOptions { ConnectionString = Configuration.Instance.GetConnectionString() }),
                    NullLogger<EFCSecurityDataProvider>.Instance)
                .InstallDatabase();

            var _ = PermissionType.See; // pre-loads the type
        }
    }
}
