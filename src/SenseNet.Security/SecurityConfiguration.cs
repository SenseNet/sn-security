using SenseNet.Security.Messaging;

namespace SenseNet.Security
{
    /// <summary>
    /// Configuration object for the security component.
    /// It is provided by the host application and used only during system start.
    /// </summary>
    public class SecurityConfiguration
    {
        /// <summary>
        /// An IMessageProvider implementation instance that will be used during the lifetime of the application.
        /// </summary>
        public IMessageProvider MessageProvider { get; set; }
        /// <summary>
        /// An ISecurityDataProvider implementation instance that will be used during the lifetime of the application.
        /// </summary>
        public ISecurityDataProvider SecurityDataProvider { get; set; }

        /// <summary>Default: -1</summary>
        public int? SystemUserId { get; set; }

        /// <summary>Default: 6</summary>
        public int? VisitorUserId { get; set; }

        /// <summary>Default: 8</summary>
        public int? EveryoneGroupId { get; set; }

        /// <summary>Default: 9</summary>
        public int? OwnerGroupId { get; set; }

        /// <summary>Default: 30</summary>
        public int? CommunicationMonitorRunningPeriodInSeconds { get; set; }

        /// <summary>Time span before executed activities are cleared from the database. Default: 42</summary>
        public int? SecuritActivityLifetimeInMinutes { get; set; } //UNDONE: TYPO

        /// <summary>Default: 120</summary>
        public int? SecuritActivityTimeoutInSeconds { get; set; } //UNDONE: TYPO
    }
}
