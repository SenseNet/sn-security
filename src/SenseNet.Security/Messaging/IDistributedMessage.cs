using System;
using System.IO;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Base interface of all message types.
    /// </summary>
    public interface IDistributedMessage
    {
        /// <summary>
        /// DateTime when the message was sent.
        /// </summary>
        DateTime MessageSent { get; set; }
        /// <summary>
        /// Information about the current sender.
        /// </summary>
        IMessageSender Sender { get; set; }
    }

    /// <summary>
    /// Represents a message from unknown source.
    /// Created by the receiver if it cannot recognize the type of the message.
    /// </summary>
    public sealed class UnknownMessage : IDistributedMessage
    {
        /// <summary>
        /// DateTime of the message sending.
        /// </summary>
        public DateTime MessageSent { get; set; }
        /// <summary>
        /// Information about the current sender.
        /// </summary>
        public IMessageSender Sender { get; set; }
        /// <summary>
        /// Received data
        /// </summary>
        public Stream MessageData { get; set; }
    }

}
