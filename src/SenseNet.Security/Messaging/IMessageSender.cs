using System;
using System.Collections.Specialized;

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

    public class MessageSenderManager : IMessageSenderManager
    {
        //UNDONE: replace constructor parameters with options object
        public MessageSenderManager(string computerId = null, string instanceId = null)
        {
            ComputerId = computerId ?? Environment.MachineName;
            InstanceId = instanceId ?? Guid.NewGuid().ToString();
        }

        public string ComputerId { get; }
        public string InstanceId { get; }

        public IMessageSender CreateMessageSender()
        {
            return new MessageSender(ComputerId, InstanceId);
        }

        public bool IsMe(IMessageSender sender)
        {
            return sender.InstanceID == InstanceId;
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
