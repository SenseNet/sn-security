using System;
using System.Collections.Generic;
using System.Threading;
using Microsoft.Extensions.Options;
using SenseNet.Diagnostics;
using SenseNet.Security.Configuration;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents a user who has permission for everything.
    /// </summary>
    internal class SecuritySystemUser : ISecurityUser
    {
        private static readonly int[] EmptyGroups = new int[0];

        public SecuritySystemUser(int id) { Id = id; }

        /// <summary>Id of the user. This value comes from Configuration.Identities.SystemUserId</summary>
        public int Id { get; }

        /// <summary>Interface implementation. Not used in this class.</summary>
        public IEnumerable<int> GetDynamicGroups(int entityId)
        {
            return EmptyGroups;
        }
    }

    /// <summary>
    /// Central object of the security subsystem.
    /// </summary>
    public class SecuritySystem
    {
        internal SecurityConfiguration Configuration { get; }
        internal MessagingOptions MessagingOptions { get; }
        public ISecurityDataProvider DataProvider { get; }
        internal DataHandler DataHandler { get; }
        public IMessageProvider MessageProvider { get; }
        public IMessageSenderManager MessageSenderManager { get; set; }
        internal SecurityCache Cache { get; private set; }
        internal CommunicationMonitor CommunicationMonitor { get; private set; }
        internal SecurityActivityQueue SecurityActivityQueue { get; private set; }
        internal SecurityEntityManager EntityManager { get; set; }
        internal IMissingEntityHandler MissingEntityHandler { get; set; }
        internal SecurityActivityHistoryController ActivityHistory { get; set; }
        internal PermissionQuery PermissionQuery { get; set; }

        private bool _killed;

        public ISecurityUser SystemUser { get; }

        /// <summary>
        /// Gets a general context for built in system user
        /// </summary>
        public SecurityContext GeneralSecurityContext { get; private set; }

        internal DateTime StartedAt { get; private set; }

        //UNDONE: get configuration through IOptions and register SecuritySystem as a service.
        public SecuritySystem(ISecurityDataProvider dataProvider, IMessageProvider messageProvider,
            IMissingEntityHandler missingEntityHandler, SecurityConfiguration configuration, MessagingOptions messagingOptions)
        {
            Configuration = configuration;
            MessagingOptions = messagingOptions;
            dataProvider.ActivitySerializer = new ActivitySerializer(this);
            DataHandler = new DataHandler(dataProvider, Options.Create(messagingOptions));
            ActivityHistory = new SecurityActivityHistoryController();
            DataProvider = dataProvider;
            MessageProvider = messageProvider;
            MessageSenderManager = messageProvider.MessageSenderManager;
            MissingEntityHandler = missingEntityHandler;
            SystemUser = new SecuritySystemUser(configuration.SystemUserId);
        }

        public void Start()
        {
            GeneralSecurityContext = null;

            // The message provider must receive ongoing activities at this time.
            StartedAt = DateTime.UtcNow;

            var uncompleted = DataHandler.LoadCompletionState(out var lastActivityIdFromDb);
            
            PermissionTypeBase.InferForcedRelations();

            using (var op = SnTrace.Security.StartOperation("Security initial loading."))
            {
                var cache = new SecurityCache(DataHandler);
                cache.Initialize();
                Cache = cache;
                op.Successful = true;
            }

            EntityManager = new SecurityEntityManager(Cache, DataHandler, MissingEntityHandler);
            Cache.EntityManager = EntityManager; // Property injection
            DataHandler.EntityManager = EntityManager; // Property injection

            PermissionQuery = new PermissionQuery(EntityManager, Cache);
            CommunicationMonitor = new CommunicationMonitor(DataHandler, Options.Create(MessagingOptions));
            GeneralSecurityContext = new SecurityContext(SystemUser, this);

            SecurityActivityQueue = new SecurityActivityQueue(this, CommunicationMonitor, DataHandler, ActivityHistory);
            SecurityActivityQueue.Startup(uncompleted, lastActivityIdFromDb);
            ActivityHistory.SecurityActivityQueue = SecurityActivityQueue; // Property injection

            MessageProvider.MessageReceived += MessageProvider_MessageReceived;
            MessageProvider.Initialize();
            MessageProvider.Start(StartedAt);

            _killed = false;
        }

        /// <summary>
        /// Stops the security subsystem.
        /// </summary>
        public void Shutdown()
        {
            if (_killed)
                return;
            _killed = true;
            MessageProvider.ShutDown();
            MessageProvider.MessageReceived -= MessageProvider_MessageReceived;
            CommunicationMonitor.Shutdown();
            SecurityActivityQueue.Shutdown();
        }


        private void MessageProvider_MessageReceived(object sender, MessageReceivedEventArgs args)
        {
            var message = args.Message;

            // debug game
            if (message is PingMessage)
            {
                MessageProvider.SendMessage(new PongMessage());
                return;
            }

            SecurityActivity activity = null;

            // load from database if it was too big to distribute
            if (message is BigActivityMessage bigActivityMessage)
            {
                activity = DataHandler.LoadBigSecurityActivityAsync(bigActivityMessage.DatabaseId, CancellationToken.None)
                    .ConfigureAwait(false).GetAwaiter().GetResult();
                if (activity == null)
                    SnTrace.Security.WriteError("Cannot load body of a BigActivity. Id: {0}", bigActivityMessage.DatabaseId);
            }

            // trying to interpret
            if (activity == null)
                activity = message as SecurityActivity;

            // Apply if everything is good
            if (activity != null)
            {
                activity.FromReceiver = true;
                activity.Context = GeneralSecurityContext;
                activity.Execute(GeneralSecurityContext, false);
            }
        }
    }
}
