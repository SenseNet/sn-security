using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Extensions.DependencyInjection;
using SenseNet.Security.Configuration;
using SenseNet.Security.Data;
using SenseNet.Security.Messaging;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class ServicesTests
    {
        [TestMethod]
        public void RegisterServices_Default()
        {
            var services = new ServiceCollection()
                .AddLogging()
                .AddSenseNetSecurity()
                .BuildServiceProvider();

            var config1 = services.GetRequiredService<IOptions<SecurityConfiguration>>();
            var config2 = services.GetRequiredService<IOptions<MessagingOptions>>();
            var dataProvider = services.GetRequiredService<ISecurityDataProvider>();
            var messageProvider = services.GetRequiredService<IMessageProvider>();
            var missingEntityHandler = services.GetRequiredService<IMissingEntityHandler>();

            Assert.IsTrue(dataProvider is MemoryDataProvider);
            Assert.IsTrue(messageProvider is DefaultMessageProvider);
            Assert.IsTrue(missingEntityHandler is MissingEntityHandler);
        }
    }
}
