using System;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Message type for debugging purposes.
    /// </summary>
    [Serializable]
    public class DebugMessage : DistributedMessage
    {
        /// <summary>
        /// Carried message.
        /// </summary>
        public string Message { get; set; }
        /// <summary>
        /// Converts the information of this instance to its equivalent string representation.
        /// </summary>
        public override string ToString()
        {
            return "DebugMessage: " + Message;
        }
    }

    /// <summary>
    /// Message type for communication testing purposes.
    /// </summary>
    [Serializable]
    public sealed class PingMessage : DebugMessage
    {
        /// <summary>
        /// Initializes a new instance of the PingMessage.
        /// </summary>
        public PingMessage()
        {
            Message = "PING";
        }
    }

    /// <summary>
    /// Message type for communication testing purposes.
    /// </summary>
    [Serializable]
    public sealed class PongMessage : DebugMessage
    {
        /// <summary>
        /// Initializes a new instance of the PongMessage.
        /// </summary>
        public PongMessage()
        {
            Message = "PONG";
        }
    }
}
