using System.Configuration;

namespace SenseNet.Security.Configuration
{
    internal static class Messaging
    {
        private static readonly string MessageProviderKey = "SecurityMessageProvider";
        private static string _messageProvider;

        public static string MessageProvider
        {
            get
            {
                if (_messageProvider == null)
                {
                    _messageProvider = ConfigurationManager.AppSettings[MessageProviderKey];
                    if (string.IsNullOrEmpty(_messageProvider))
                        _messageProvider = string.Empty;
                }

                return _messageProvider;
            }
        }

        private static readonly string DistributableSecurityActivityMaxSizeKey = "DistributableSecurityActivityMaxSize";
        private static int? _distributableSecurityActivityMaxSize;

        public static int DistributableSecurityActivityMaxSize
        {
            get
            {
                if (!_distributableSecurityActivityMaxSize.HasValue)
                {
                    int intValue;
                    var value = ConfigurationManager.AppSettings[DistributableSecurityActivityMaxSizeKey];
                    if (!int.TryParse(value, out intValue))
                        intValue = 200000;
                    _distributableSecurityActivityMaxSize = intValue;
                }

                return _distributableSecurityActivityMaxSize.Value;
            }
        }
        public static int CommunicationMonitorRunningPeriodInSeconds { get; internal set; }

        public static int SecuritActivityLifetimeInMinutes { get; internal set; }
        public static int SecuritActivityTimeoutInSeconds { get; internal set; }

        internal static readonly int SecurityActivityExecutionLockRefreshPeriodInSeconds = 10;
        internal static readonly int SecurityActivityExecutionLockTimeoutInSeconds = 25;

        private static readonly string MessageProcessorThreadCountKey = "MessageProcessorThreadCount";
        private static int? _messageProcessorThreadCount;
        /// <summary>
        /// Number of message processor threads. Default is 3.
        /// </summary>
        public static int MessageProcessorThreadCount
        {
            get
            {
                if (!_messageProcessorThreadCount.HasValue)
                {
                    var setting = ConfigurationManager.AppSettings[MessageProcessorThreadCountKey];
                    if (string.IsNullOrEmpty(setting) || !int.TryParse(setting, out var value))
                        value = 3;
                    _messageProcessorThreadCount = value;
                }
                return _messageProcessorThreadCount.Value;
            }
        }

        private static readonly string MessageProcessorThreadMaxMessagesKey = "MessageProcessorThreadMaxMessages";
        private static int? _messageProcessorThreadMaxMessages;
        /// <summary>
        /// Max number of messages processed by a single message processor thread. Default is 100.
        /// </summary>
        public static int MessageProcessorThreadMaxMessages
        {
            get
            {
                if (!_messageProcessorThreadMaxMessages.HasValue)
                {
                    var setting = ConfigurationManager.AppSettings[MessageProcessorThreadMaxMessagesKey];
                    if (string.IsNullOrEmpty(setting) || !int.TryParse(setting, out var value))
                        value = 100;
                    _messageProcessorThreadMaxMessages = value;
                }
                return _messageProcessorThreadMaxMessages.Value;
            }
        }
    }
}
