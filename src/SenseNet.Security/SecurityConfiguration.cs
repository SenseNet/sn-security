using System;
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

        public IMissingEntityHandler MissingEntityHandler { get; set; } = new MissingEntityHandler();

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

        [Obsolete("Use the overload with correct name.", true)]
        public int? SecuritActivityLifetimeInMinutes
        {
            get => SecurityActivityLifetimeInMinutes;
            set => SecurityActivityLifetimeInMinutes = value;
        }
        /// <summary>Time span before executed activities are cleared from the database. Default: 42</summary>
        public int? SecurityActivityLifetimeInMinutes { get; set; }

        [Obsolete("Use the overload with correct name.", true)]
        public int? SecuritActivityTimeoutInSeconds
        {
            get => SecurityActivityTimeoutInSeconds;
            set => SecurityActivityTimeoutInSeconds = value;
        }
        /// <summary>Default: 120</summary>
        public int? SecurityActivityTimeoutInSeconds { get; set; }
    }
}
