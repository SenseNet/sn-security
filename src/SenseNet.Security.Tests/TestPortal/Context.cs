using System;
using SenseNet.Security.Messaging;
using System.Diagnostics;
using System.IO;
using SenseNet.Diagnostics;
using SenseNet.Tools;

namespace SenseNet.Security.Tests.TestPortal
{
    public class Context
    {
        // Called by tests. The messageProvider must be initialized.
        internal static SecuritySystem StartTheSystem(ISecurityDataProvider securityDataProvider, IMessageProvider messageProvider, TextWriter traceChannel = null)
        {
            var securitySystem = new SecuritySystem(securityDataProvider, messageProvider,
                new MissingEntityHandler(),
                new SecurityConfiguration {CommunicationMonitorRunningPeriodInSeconds = 31});
            securitySystem.Start();

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
