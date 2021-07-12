using System;
using System.Collections.Generic;
using SenseNet.Diagnostics;
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

        /// <summary>Interface implementation. Not used in this class.</summary>
        public IEnumerable<int> GetDynamicGroups(int entityId)
        {
            return EmptyGroups;
        }

        /// <summary>Id of the user. This value comes from Configuration.Identities.SystemUserId</summary>
        public int Id => Configuration.Identities.SystemUserId;
    }

    /// <summary>
    /// Central object of the security subsystem.
    /// </summary>
    public class SecuritySystem
    {
        //UNDONE: REMOVE: public static SecuritySystem.Instance
        public static SecuritySystem Instance { get; private set; }

        /// <summary>
        /// Starts the security subsystem using the passed configuration.
        /// Call this method only once in your application's startup sequence.
        /// The method prepares and memorizes the main components for 
        /// creating SecurityContext instances in a fastest possible way.
        /// The main components are global objects: 
        /// ISecurityDataProvider instance, IMessageProvider instance and SecurityCache instance.
        /// </summary>
        //UNDONE: REMOVE: public static void StartTheSystem(SecurityConfiguration configuration)
        public static void StartTheSystem(SecurityConfiguration configuration)
        {
            var ss = new SecuritySystem(configuration.SecurityDataProvider, configuration.MessageProvider,
                configuration.MissingEntityHandler, configuration);
            Instance = ss;
            ss.Start();
        }


        public ISecurityDataProvider SecurityDataProvider { get; }
        internal DataHandler DataHandler { get; }
        public IMessageProvider MessageProvider { get; }
        internal IMessageSenderManager MessageSenderManager { get; set; }
        internal SecurityCache Cache { get; private set; }
        internal CommunicationMonitor CommunicationMonitor { get; private set; }
        internal SecurityActivityQueue SecurityActivityQueue { get; private set; }
        internal SecurityEntityManager EntityManager { get; set; }
        internal IMissingEntityHandler MissingEntityHandler { get; set; }
        internal SecurityActivityHistoryController ActivityHistory { get; set; }
        internal PermissionQuery PermissionQuery { get; set; }

        private readonly SecurityConfiguration _configuration;
        private bool _killed;

        public ISecurityUser SystemUser { get; } = new SecuritySystemUser();

        /// <summary>
        /// Gets a general context for built in system user
        /// </summary>
        public SecurityContext GeneralSecurityContext { get; private set; }

        internal DateTime StartedAt { get; private set; }


        public SecuritySystem(ISecurityDataProvider securityDataProvider, IMessageProvider messageProvider,
            IMissingEntityHandler missingEntityHandler, SecurityConfiguration configuration)
        {
            SnTrace.Write("<SecuritySystem ctor");
            DataHandler = new DataHandler(this);
            ActivityHistory = new SecurityActivityHistoryController();
            SecurityDataProvider = securityDataProvider;
            MessageProvider = messageProvider;
            MessageSenderManager = new MessageSenderManager();
            MissingEntityHandler = missingEntityHandler;
            _configuration = configuration;
            SnTrace.Write("SecuritySystem ctor>");
        }

        public void Start()
        {
            SnTrace.Write("<SecuritySystem Start");
            GeneralSecurityContext = null;

            // The message provider must receive ongoing activities at this time.
            StartedAt = DateTime.UtcNow;

            var uncompleted = DataHandler.LoadCompletionState(SecurityDataProvider, out var lastActivityIdFromDb);

            MessageProvider.MessageReceived += MessageProvider_MessageReceived;

            Configuration.Identities.SystemUserId = _configuration.SystemUserId ?? -1;
            Configuration.Identities.VisitorUserId = _configuration.VisitorUserId ?? 6;
            Configuration.Identities.EveryoneGroupId = _configuration.EveryoneGroupId ?? 8;
            Configuration.Identities.OwnerGroupId = _configuration.OwnerGroupId ?? 9;

            Configuration.Messaging.CommunicationMonitorRunningPeriodInSeconds = _configuration.CommunicationMonitorRunningPeriodInSeconds ?? 30;
            Configuration.Messaging.SecurityActivityLifetimeInMinutes = _configuration.SecurityActivityLifetimeInMinutes ?? 42;
            Configuration.Messaging.SecurityActivityTimeoutInSeconds = _configuration.SecurityActivityTimeoutInSeconds ?? 120;

            PermissionTypeBase.InferForcedRelations();

            using (var op = SnTrace.Security.StartOperation("Security initial loading."))
            {
                var cache = new SecurityCache(this);
                cache.Initialize();
                Cache = cache;
                op.Successful = true;
            }

            EntityManager = new SecurityEntityManager(SecurityDataProvider, Cache, MissingEntityHandler);

            PermissionQuery = new PermissionQuery(EntityManager, Cache);

            CommunicationMonitor = new CommunicationMonitor(this);

            GeneralSecurityContext = new SecurityContext(SystemUser, this);

            SecurityActivityQueue = new SecurityActivityQueue(this);
            SecurityActivityQueue.Startup(uncompleted, lastActivityIdFromDb);

            _killed = false;
            SnTrace.Write("SecuritySystem Start>");
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
                activity = DataHandler.LoadBigSecurityActivity(bigActivityMessage.DatabaseId);
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
                activity.Execute(GeneralSecurityContext, false);
            }
        }
    }
}
