﻿using System;
using SenseNet.Security.Messaging;
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
        public static SecuritySystem StartTheSystem(ISecurityDataProvider securityDataProvider)
        {
            // Get configured or default messaging component and initialize it.
            var messageProvider = ResolveMessageProvider();
            messageProvider.Initialize();

            // call the second step
            Debug.WriteLine("SECU> StartTheSystem: " + securityDataProvider.GetType().Name);
            var securitySystem = StartTheSystem(securityDataProvider, messageProvider);

            // legacy logic
            // original line: MessageSender.Initialize(messageProvider.ReceiverName);
            securitySystem.MessageSenderManager = new MessageSenderManager(messageProvider.ReceiverName);

            return securitySystem;
        }
        // Called by tests. The messageProvider must be initialized.
        internal static SecuritySystem StartTheSystem(ISecurityDataProvider securityDataProvider, IMessageProvider messageProvider, TextWriter traceChannel = null)
        {
            var securitySystem = new SecuritySystem(securityDataProvider, messageProvider,
                new MissingEntityHandler(),
                new SecurityConfiguration {CommunicationMonitorRunningPeriodInSeconds = 31});
            securitySystem.Start();

            return securitySystem;
        }

        private static IMessageProvider ResolveMessageProvider()
        {
            IMessageProvider messageProvider;
            try
            {
                var channelAdapterType = GetMessageProviderType();
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
            var channelProviderTypeName = Configuration.Messaging.MessageProvider;
            if (string.IsNullOrEmpty(channelProviderTypeName))
                return typeof(DefaultMessageProvider);

            var channelAdapterType = TypeResolver.GetType(channelProviderTypeName, false);
            if (channelAdapterType == null)
                throw new ArgumentException("MessageProvider is not correctly configured.");

            return channelAdapterType;
        }

        public Context(ISecurityUser currentUser, SecuritySystem securitySystem)
        {
            // Create a new instance.
            Security = new SecurityContext(currentUser, securitySystem);
        }

        public SecurityContext Security { get; set; }
    }
}
