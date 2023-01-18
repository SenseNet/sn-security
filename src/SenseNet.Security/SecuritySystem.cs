using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
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
        internal ISecurityActivityQueue SecurityActivityQueue { get; private set; }
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

        //UNDONE:DI register SecuritySystem as a service.
        public SecuritySystem(
            ISecurityDataProvider dataProvider,
            IMessageProvider messageProvider,
            ISecurityMessageFormatter messageFormatter,
            IMissingEntityHandler missingEntityHandler,
            IOptions<SecurityConfiguration> configuration,
            IOptions<MessagingOptions> messagingOptions)
        {
            Configuration = configuration?.Value ?? new SecurityConfiguration();
            MessagingOptions = messagingOptions?.Value ?? new MessagingOptions();
            //UNDONE:DI: Initialize through ctor of implementations
            dataProvider.ActivitySerializer = new ActivitySerializer(this, messageFormatter);
            DataHandler = new DataHandler(dataProvider, messagingOptions);
            ActivityHistory = new SecurityActivityHistoryController();
            DataProvider = dataProvider;
            MessageProvider = messageProvider;
            MessageSenderManager = messageProvider.MessageSenderManager;
            MissingEntityHandler = missingEntityHandler;
            SystemUser = new SecuritySystemUser(Configuration.SystemUserId);
        }

        [Obsolete("Use async version instead.")]
        public void Start()
        {
            StartAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task StartAsync(CancellationToken cancel, bool legacy = true)
        {
            GeneralSecurityContext = null;

            // The message provider must receive ongoing activities at this time.
            StartedAt = DateTime.UtcNow;

            var dbResult = await DataHandler.LoadCompletionStateAsync(cancel).ConfigureAwait(false);
            var uncompleted = dbResult.CompletionState;
            var lastActivityIdFromDb = dbResult.LastDatabaseId;
            
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

            SecurityActivityQueue = legacy
                ? new SecurityActivityQueue_Legacy(this, CommunicationMonitor, DataHandler, ActivityHistory)
                : SecurityActivityQueue = new SecurityActivityQueue(DataHandler);
            await SecurityActivityQueue.StartAsync(uncompleted, lastActivityIdFromDb, cancel);

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
                SnTrace.Security.Write($"Loading big activity message with id {bigActivityMessage.DatabaseId}");

                activity = DataHandler.LoadBigSecurityActivityAsync(bigActivityMessage.DatabaseId, CancellationToken.None)
                    .GetAwaiter().GetResult();
                if (activity == null)
                    SnTrace.Security.WriteError("Cannot load body of a BigActivity. Id: {0}", bigActivityMessage.DatabaseId);
            }

            // trying to interpret
            activity ??= message as SecurityActivity;

            // Apply if everything is good
            if (activity != null)
            {
                SnTrace.Security.Write($"Executing {activity.GetType().Name} security activity.");

                activity.FromReceiver = true;
                activity.Context = GeneralSecurityContext;
                activity.Execute(GeneralSecurityContext, false);
            }
            else
            {
                SnTrace.Security.Write($"Security activity received but it is null.");
            }
        }
    }
}
