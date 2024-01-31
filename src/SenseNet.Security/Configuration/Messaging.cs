using SenseNet.Tools.Configuration;

namespace SenseNet.Security.Configuration;

internal static class Messaging
{
    internal static readonly int SecurityActivityExecutionLockRefreshPeriodInSeconds = 10;
    internal static readonly int SecurityActivityExecutionLockTimeoutInSeconds = 25;
}

[OptionsClass(sectionName: "sensenet:security:messaging")]
public class MessagingOptions
{
    /// <summary>
    /// Maximum size of a security activity distributed through messaging.
    /// Activities bigger than this will be loaded from the database
    /// on the target server. Default is 200000 bytes.
    /// </summary>
    public int DistributableSecurityActivityMaxSize { get; set; } = 200000;
    /// <summary>
    /// Health check and cleanup monitor execution period. Default: 30 seconds.
    /// </summary>
    public int CommunicationMonitorRunningPeriodInSeconds { get; set; } = 30;
    /// <summary>
    /// Waiting period after an activity is deleted. Default: 42 minutes.
    /// </summary>
    public int SecurityActivityLifetimeInMinutes { get; set; } = 42;
    /// <summary>
    /// Waiting period after a long-running activity fails. Default: 120 seconds.
    /// </summary>
    public int SecurityActivityTimeoutInSeconds { get; set; } = 120;
    /// <summary>
    /// Number of message processor threads. Default is 3.
    /// </summary>
    public int MessageProcessorThreadCount { get; set; } = 3;
    /// <summary>
    /// Maximum number of messages processed by a single message processor thread. Default is 100.
    /// </summary>
    public int MessageProcessorThreadMaxMessages { get; set; } = 100;
}