namespace SenseNet.Security.Messaging.Msmq
{
    public class MsmqOptions
    {
        public string MessageQueueName { get; set; } = string.Empty;

        /// <summary>
        /// Retention time of messages in the message queue in seconds. Default: 10, minimum: 2.
        /// </summary>
        public int MessageRetentionTime { get; set; } = 10;

        /// <summary>
        /// Defines the time interval between reconnect attempts in seconds. Default value: 30 seconds.
        /// </summary>
        public int MsmqReconnectDelay { get; set; } = 30;
    }
}
