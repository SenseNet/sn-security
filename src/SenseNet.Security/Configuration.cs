using System.Configuration;

namespace SenseNet.Security
{
    internal static class Configuration
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

        public static int SystemUserId { get; internal set; }
        public static int VisitorUserId { get; internal set; }
        public static int EveryoneGroupId { get; internal set; }
        public static int OwnerGroupId { get; internal set; }

        public static int CommunicationMonitorRunningPeriodInSeconds { get; internal set; }
        public static int SecuritActivityLifetimeInMinutes { get; internal set; }
        public static int SecuritActivityTimeoutInSeconds { get; internal set; }

        internal static readonly int SecurityActivityExecutionLockRefreshPeriodInSeconds = 10;
        internal static readonly int SecurityActivityExecutionLockTimeoutInSeconds = 25;
    }
}
