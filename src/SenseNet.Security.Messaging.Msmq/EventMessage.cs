namespace SenseNet.Security.Messaging.Msmq
{
    internal class EventMessage
    {
        internal class Errors
        {
            internal const string SendError = "An error occured during sending a message.";
            internal const string ReceiveError = "An error occurred when receiving from the queue ({0}).";
            internal const string ProcessingError = "An error occured during processing a message.";
            internal const string SerializationError = "An error occured during serializing a message.";
            internal const string DeserializationError = "An error occured during deserializing a message.";
            internal const string RepairError = "An error occured during repairing message queues.";
        }
    }
}
