using System;
using SenseNet.Security.Messaging;
using System.IO;
using System.Threading;
using Microsoft.Extensions.Options;
using SenseNet.Security.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SenseNet.Extensions.DependencyInjection;

namespace SenseNet.Security.Tests.TestPortal
{
    public class Context
    {
        // Called by tests. The messageProvider must be initialized.
        internal static SecuritySystem StartTheSystem (
            ISecurityDataProvider securityDataProvider,
            IMessageProvider messageProvider,
            TextWriter traceChannel = null,
            Action<IServiceCollection> configureServices = null)
        {
            var serviceCollection = new ServiceCollection()
                .AddLogging()
                .AddDefaultSecurityMessageTypes()
                .AddSingleton<ISecurityMessageFormatter, SnSecurityMessageFormatter>();
            configureServices?.Invoke(serviceCollection);
            var services = serviceCollection.BuildServiceProvider();

            var securitySystem = new SecuritySystem(securityDataProvider, messageProvider,
                services.GetRequiredService<ISecurityMessageFormatter>(),
                new MissingEntityHandler(),
                Options.Create(new SecurityConfiguration()),
                Options.Create(new MessagingOptions {CommunicationMonitorRunningPeriodInSeconds = 31}),
                services.GetRequiredService<ILogger<SecuritySystem>>());
            securitySystem.StartAsync(CancellationToken.None).GetAwaiter().GetResult();

            return securitySystem;
        }

        public Context(ISecurityUser currentUser, SecuritySystem securitySystem)
        {
            // Create a new instance.
            Security = new SecurityContext(currentUser, securitySystem);
        }

        public SecurityContext Security { get; set; }
    }
}
