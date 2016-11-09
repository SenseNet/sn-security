using System;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Represents a placeholder message that is sent in place of the original one that contains a huge amount of data.
    /// On the receiver side the whole message can be loaded from the database by the carried message id.
    /// </summary>
    [Serializable]
    public class BigActivityMessage : DistributedMessage
    {
        /// <summary>
        /// Message id in the database.
        /// </summary>
        public int DatabaseId { get; set; }
    }
}
