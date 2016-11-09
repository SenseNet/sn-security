namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Represents information about the sender of the message
    /// </summary>
    public interface IMessageSender
    {
        /// <summary>
        /// Computer identifier. Must be unique in the cluster (computers that can interact through messaging).
        /// </summary>
        string ComputerID { get; }
        /// <summary>
        /// Technical identifier. Must be unique.
        /// </summary>
        string InstanceID { get; }
        /// <summary>
        /// Returs true if the message was sent from the current appdomain.
        /// </summary>
        bool IsMe { get; }
    }
}
