using System;
using SenseNet.Security.Messaging;
using System.IO;
using System.Threading;
using Microsoft.Extensions.Options;
using SenseNet.Security.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SenseNet.Security.Tests.TestPortal
{
    public class Context
    {
        // Called by tests. The messageProvider must be initialized.
        internal static SecuritySystem StartTheSystem (
            ISecurityDataProvider securityDataProvider,
            IMessageProvider messageProvider,
            TextWriter traceChannel = null,
            Action<IServiceCollection> configureServices = null,
            bool legacy = true
            )
        {
            var serviceCollection = new ServiceCollection()
                .AddDefaultSecurityMessageTypes()
                .AddSingleton<ISecurityMessageFormatter, SnSecurityMessageFormatter>();
            configureServices?.Invoke(serviceCollection);
            var services = serviceCollection.BuildServiceProvider();

            var securitySystem = new SecuritySystem(securityDataProvider, messageProvider,
                services.GetRequiredService<ISecurityMessageFormatter>(),
                new MissingEntityHandler(),
                Options.Create(new SecurityConfiguration()),
                Options.Create(new MessagingOptions {CommunicationMonitorRunningPeriodInSeconds = 31}));
            securitySystem.StartAsync(CancellationToken.None, legacy).GetAwaiter().GetResult();

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
