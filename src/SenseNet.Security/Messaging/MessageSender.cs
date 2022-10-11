using System;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Represents a message sender.
    /// </summary>
    [Serializable]
    public class MessageSender : IMessageSender
    {
        /// <summary>
        /// Gets an id to identify computers. This is an invariant value that comes typically
        /// from the ReceiverName property of the initialized IMessageProvider implementation instance.
        /// </summary>
        public string ComputerID { get; set; }

        /// <summary>
        /// Gets an unique identifier that is used during the lifetime of the current AppDomain. This is an invariant value.
        /// </summary>
        public string InstanceID { get; set; }

        public MessageSender() { }

        internal MessageSender(string computerId, string instanceId)
        {
            ComputerID = computerId;
            InstanceID = instanceId;
        }

    }
}
