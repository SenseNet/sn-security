using System;
using Newtonsoft.Json;

namespace SenseNet.Security.Messaging
{
    public class ImplementationTypeConverter<T> : JsonConverter
    {
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            serializer.Serialize(writer, value);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            return serializer.Deserialize<T>(reader);
        }

        public override bool CanConvert(Type objectType)
        {
            return true;
        }
    }

    /// <summary>
    /// Base class of any kind of messages in the security system.
    /// Implements the IDistributedMessage interface.
    /// </summary>
    [Serializable]
    public abstract class DistributedMessage : IDistributedMessage
    {
        /// <summary>
        /// DateTime of the message sending.
        /// </summary>
        public DateTime MessageSent { get; set; }

        /// <summary>
        /// Information about the current sender.
        /// </summary>
        [JsonConverter(typeof(ImplementationTypeConverter<MessageSender>))]
        public IMessageSender Sender { get; set; }


        [NonSerialized]
        private int _bodySize;
        internal int BodySize
        {
            get => _bodySize;
            set => _bodySize = value;
        }
    }
}
