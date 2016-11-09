using System;
using System.Configuration;

namespace SenseNet.Security.Messaging.Msmq
{
    internal static class Configuration
    {
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
                    int value;
                    var setting = ConfigurationManager.AppSettings[MessageRetentionTimeKey];
                    if (String.IsNullOrEmpty(setting) || !Int32.TryParse(setting, out value))
                        value = 10;
                    if (value < 2)
                        value = 2;
                    _messageRetentionTime = value;
                }
                return _messageRetentionTime.Value;
            }
        }

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
                    int value;
                    var setting = ConfigurationManager.AppSettings[MessageProcessorThreadCountKey];
                    if (String.IsNullOrEmpty(setting) || !Int32.TryParse(setting, out value))
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
                    int value;
                    var setting = ConfigurationManager.AppSettings[MessageProcessorThreadMaxMessagesKey];
                    if (String.IsNullOrEmpty(setting) || !Int32.TryParse(setting, out value))
                        value = 100;
                    _messageProcessorThreadMaxMessages = value;
                }
                return _messageProcessorThreadMaxMessages.Value;
            }
        }

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
                    int value;
                    var setting = ConfigurationManager.AppSettings[MsmqReconnectDelayKey];
                    if (String.IsNullOrEmpty(setting) || !Int32.TryParse(setting, out value))
                        value = 30;
                    _msmqReconnectDelay = value * 1000;
                }
                return _msmqReconnectDelay.Value;
            }
        }

    }
}
