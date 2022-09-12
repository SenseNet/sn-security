using SenseNet.Security.Messaging;
using System.IO;
using System.Threading;
using SenseNet.Security.Configuration;

namespace SenseNet.Security.Tests.TestPortal
{
    public class Context
    {
        // Called by tests. The messageProvider must be initialized.
        internal static SecuritySystem StartTheSystem(ISecurityDataProvider securityDataProvider,
            IMessageProvider messageProvider, TextWriter traceChannel = null)
        {
            var securitySystem = new SecuritySystem(securityDataProvider, messageProvider,
                new MissingEntityHandler(),
                new SecurityConfiguration(),
                new MessagingOptions { CommunicationMonitorRunningPeriodInSeconds = 31 });
            securitySystem.StartAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();

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
