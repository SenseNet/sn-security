using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SenseNet.Security.EFCSecurityStore.Configuration;
using SenseNet.Security.Tests;

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
//new EFCSecurityDataProvider(new MessageSenderManager(
//        new OptionsWrapper<MessageSenderOptions>(
//            new MessageSenderOptions())), 0, Configuration.Instance.GetConnectionString())
            new EFCSecurityDataProvider(
                    messageSenderManager: DiTools.CreateMessageSenderManager(),
                    options: new OptionsWrapper<DataOptions>(
                        new DataOptions { ConnectionString = Configuration.Instance.GetConnectionString() }),
                    logger: NullLoggerFactory.Instance.CreateLogger<EFCSecurityDataProvider>())
                .InstallDatabase();

            var _ = PermissionType.See; // pre-loads the type
        }
    }
}
