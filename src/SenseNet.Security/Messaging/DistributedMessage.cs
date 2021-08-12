using System;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Base class of any kind of messages in the security system.
    /// Implements the IDistributedMessage interface.
    /// </summary>
    [Serializable]
    public abstract class DistributedMessage : IDistributedMessage
    {
        /// <summary>
        /// DateTime of the message sending.
        /// </summary>
        public DateTime MessageSent { get; set; }

        /// <summary>
        /// Information about the current sender.
        /// </summary>
        public IMessageSender Sender { get; set; }


        [NonSerialized]
        private int _bodySize;
        internal int BodySize
        {
            get => _bodySize;
            set => _bodySize = value;
        }
    }
}
