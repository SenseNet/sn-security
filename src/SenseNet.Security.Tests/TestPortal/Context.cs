using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Runtime.Remoting.Contexts;
using SenseNet.Security;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;
using System.Diagnostics;
using System.IO;
using SenseNet.Diagnostics;
using SenseNet.Tools;

namespace SenseNet.Security.Tests.TestPortal
{
    public class Context
    {
        /// <summary>
        /// Building and connecting necessary LEGO bricks.
        /// One of the possible comfortable solution. Every component is stateless so we can be stored for long time.
        /// </summary>
        public static void StartTheSystem(ISecurityDataProvider securityDataProvider)
        {
            // Get configured or default messaging component and initialize it.
            var messageProvider = ResolveMessageProvider();
            messageProvider.Initialize();
            MessageSender.Initialize(messageProvider.ReceiverName);

            // call the second step
            Debug.WriteLine("SECU> StartTheSystem: " + securityDataProvider.GetType().Name);
            StartTheSystem(securityDataProvider, messageProvider);
        }
        // Called by tests. The messageProvider must be initialized.
        internal static void StartTheSystem(ISecurityDataProvider securityDataProvider, IMessageProvider messageProvider, TextWriter traceChannel = null)
        {
            // Timestamp of the starting.
            var startingThesystem = DateTime.UtcNow;
            // Call SecurityContext starter method.
            TestSecurityContext.StartTheSystem(new SecurityConfiguration
            {
                SecurityDataProvider = securityDataProvider,
                MessageProvider = messageProvider,
                CommunicationMonitorRunningPeriodInSeconds = 31,
            });
            // Staring message system. Messages before 'startingThesystem' will be ignored.
            messageProvider.Start(startingThesystem);
        }

        private static IMessageProvider ResolveMessageProvider()
        {
            IMessageProvider messageProvider = null;
            try
            {
                Type channelAdapterType = GetMessageProviderType();
                messageProvider = (IMessageProvider)Activator.CreateInstance(channelAdapterType);
            }
            catch (Exception e) //logged, rethrown
            {
                SnLog.WriteException(e, EventMessage.Error.SystemStart, EventId.Error.SystemStart);
                throw;
            }
            return messageProvider;
        }
        private static Type GetMessageProviderType()
        {
            string channelProviderTypeName = Configuration.MessageProvider;
            if (string.IsNullOrEmpty(channelProviderTypeName))
                return typeof(DefaultMessageProvider);

            var channelAdapterType = TypeResolver.GetType(channelProviderTypeName, false);
            if (channelAdapterType == null)
                throw new ArgumentException("MessageProvider is not correctly configured.");

            return channelAdapterType;
        }

        public Context(ISecurityUser currentUser)
        {
            // Create a new instance.
            Security = new TestSecurityContext(currentUser);
        }

        public TestSecurityContext Security { get; private set; }
    }
}
