using System;

namespace SenseNet.Security
{
    /// <summary>
    /// Configuration object for the security component.
    /// It is provided by the host application and used only during system start.
    /// </summary>
    public class SecurityConfiguration
    {
        /// <summary>Default: -1</summary>
        public int SystemUserId { get; set; } = -1;

        /// <summary>Default: 6</summary>
        public int VisitorUserId { get; set; } = 6;

        /// <summary>Default: 8</summary>
        public int EveryoneGroupId { get; set; } = 8;

        /// <summary>Default: 9</summary>
        public int OwnerGroupId { get; set; } = 9;

        [Obsolete("Use MessagingOptions instead.", true)]
        public int? SecurityActivityLifetimeInMinutes { get; set; }

        [Obsolete("Use MessagingOptions instead.", true)]
        public int? SecurityActivityTimeoutInSeconds { get; set; }
    }
}
