using System;
using System.Configuration;

namespace SenseNet.Security.Messaging.Msmq
{
    internal static class Configuration
    {
        // ReSharper disable once ConvertToConstant.Local
        private static readonly string MessageQueueNameKey = "SecurityMsmqChannelQueueName";
        private static string _messageQueueName;
        public static string MessageQueueName
        {
            get
            {
                if (_messageQueueName == null)
                {
                    _messageQueueName = ConfigurationManager.AppSettings[MessageQueueNameKey];
                    if (String.IsNullOrEmpty(_messageQueueName))
                        _messageQueueName = String.Empty;
                }
                return _messageQueueName;
            }
        }

        // ReSharper disable once ConvertToConstant.Local
        private static readonly string MessageRetentionTimeKey = "MessageRetentionTime";
        private static int? _messageRetentionTime;
        /// <summary>
        /// Retention time of messages in the message queue in seconds. Default: 10, minimum: 2
        /// </summary>
        public static int MessageRetentionTime
        {
            get
            {
                if (_messageRetentionTime == null)
                {
                    var setting = ConfigurationManager.AppSettings[MessageRetentionTimeKey];
                    if (String.IsNullOrEmpty(setting) || !Int32.TryParse(setting, out var value))
                        value = 10;
                    if (value < 2)
                        value = 2;
                    _messageRetentionTime = value;
                }
                return _messageRetentionTime.Value;
            }
        }
        
        // ReSharper disable once ConvertToConstant.Local
        private static readonly string MsmqReconnectDelayKey = "MsmqReconnectDelay";
        private static int? _msmqReconnectDelay;
        /// <summary>
        /// Defines the time interval between reconnect attempts (in seconds).  Default value: 30 sec.
        /// </summary>
        internal static int MsmqReconnectDelay
        {
            get
            {
                if (!_msmqReconnectDelay.HasValue)
                {
                    var setting = ConfigurationManager.AppSettings[MsmqReconnectDelayKey];
                    if (String.IsNullOrEmpty(setting) || !Int32.TryParse(setting, out var value))
                        value = 30;
                    _msmqReconnectDelay = value * 1000;
                }
                return _msmqReconnectDelay.Value;
            }
        }
    }
}
