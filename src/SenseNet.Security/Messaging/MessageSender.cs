using System;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Represents a message sender.
    /// </summary>
    [Serializable]
    public class MessageSender : IMessageSender
    {
        private static string _computerID;

        private MessageSender() { }

        /// <summary>
        /// Gets an id to identify computers. This is an invariant value that comes tipically
        /// from the ReceiverName property of the initialized IMessageProvider implementation instance.
        /// </summary>
        public string ComputerID => _computerID;

        /// <summary>
        /// Gets an unique identifier that is used during the lifetime of the current AppDomain. This is an invariant value.
        /// </summary>
        public string InstanceID { get; private set; }
        /// <summary>
        /// Computed property. The value is true if this message is sent from this computer.
        /// </summary>
        public bool IsMe => this.InstanceID == _current.InstanceID;

        private static readonly MessageSender _current = new MessageSender { InstanceID = Guid.NewGuid().ToString() };

        internal static void Initialize(string computerID)
        {
            _computerID = computerID;
        }

        /// <summary>
        /// Creates a new MessageSender instance.
        /// </summary>
        public static MessageSender Create()
        {
            return new MessageSender { InstanceID = _current.InstanceID };
        }

    }
}
