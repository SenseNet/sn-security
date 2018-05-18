namespace SenseNet.Security
{
    internal static class EventMessage
    {
        internal static class Information
        {
            internal static readonly string StartTheSystem = "Executing unprocessed security activities.";
            internal static readonly string ExecutingUnprocessedActivitiesFinished = "Executing unprocessed security activities ({0}) finished.";
        }
        internal static class Error
        {
            internal static string HealthCheck = "An error occured during security health check execution.";
            internal static string Serialization = "An error occured during serializing a SecurityActivity.";
            internal static string Deserialization = "An error occured during deserializing a SecurityActivity.";

            internal const string MessageSerialization = "An error occured during serializing a message.";
            internal const string MessageDeserialization = "An error occured during deserializing a message.";
            internal const string MessageProcessing = "An error occured during processing a message.";
        }
    }
}
