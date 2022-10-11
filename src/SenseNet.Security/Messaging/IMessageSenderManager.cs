using System;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Manages the <see cref="IMessageSender"/> objects.
    /// </summary>
    public interface IMessageSenderManager
    {
        string ComputerId { get; }
        string InstanceId { get; }

        /// <summary>
        /// Creates a new <see cref="IMessageSender"/> instance.
        /// </summary>
        IMessageSender CreateMessageSender();
        /// <summary>
        /// Returns true if the message was sent from the current appdomain.
        /// </summary>
        bool IsMe(IMessageSender sender);
    }
}
