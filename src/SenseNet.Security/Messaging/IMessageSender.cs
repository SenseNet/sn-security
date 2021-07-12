using System;
using System.Collections.Specialized;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Manages the <see cref="IMessageSender"/> objects.
    /// </summary>
    public interface IMessageSenderManager
    {
        /// <summary>
        /// Creates a new <see cref="IMessageSender"/> instance.
        /// </summary>
        IMessageSender CreateMessageSender();
        /// <summary>
        /// Returns true if the message was sent from the current appdomain.
        /// </summary>
        bool IsMe(IMessageSender sender);
    }

    internal class MessageSenderManager : IMessageSenderManager
    {
        private readonly string _computerId;
        private readonly string _instanceId;

        public MessageSenderManager(string computerId = null, string instanceId = null)
        {
            _computerId = computerId ?? Environment.MachineName;
            _instanceId = instanceId ?? Guid.NewGuid().ToString();
        }

        public IMessageSender CreateMessageSender()
        {
            return new MessageSender(_computerId, _instanceId);
        }

        public bool IsMe(IMessageSender sender)
        {
            return sender.InstanceID == _instanceId;
        }
    }

    /// <summary>
    /// Represents information about the sender of the message
    /// </summary>
    public interface IMessageSender
    {
        /// <summary>
        /// Computer identifier. Must be unique in the cluster (computers that can interact through messaging).
        /// </summary>
        // ReSharper disable once InconsistentNaming
        string ComputerID { get; }
        /// <summary>
        /// Technical identifier. Must be unique.
        /// </summary>
        // ReSharper disable once InconsistentNaming
        // ReSharper disable once UnusedMemberInSuper.Global
        string InstanceID { get; }
    }
}
