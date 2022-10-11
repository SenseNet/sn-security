using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SenseNet.Security.Messaging
{
    public class DistributedMessageType
    {
        public Type MessageType;

        public DistributedMessageType(Type messageType)
        {
            MessageType = messageType;
        }
    }

    public class SnSecurityMessageFormatter : ISecurityMessageFormatter
    {
        private class Envelope
        {
            public string Type { get; set; }
            public IDistributedMessage Msg { get; set; }
        }

        private readonly Dictionary<string, Type> _knownMessageTypes;
        private readonly JsonSerializerSettings _serializationSettings;

        public SnSecurityMessageFormatter(IEnumerable<DistributedMessageType> knownMessageTypes,
            IEnumerable<JsonConverter> jsonConverters)
        {
            _knownMessageTypes = knownMessageTypes
                .Select(x => x.MessageType)
                .Distinct()
                .ToDictionary(x => x.FullName, x => x);
            _serializationSettings = new JsonSerializerSettings
            {
                Converters = jsonConverters.ToList(),
                NullValueHandling = NullValueHandling.Ignore,
                DateTimeZoneHandling = DateTimeZoneHandling.Utc,
                Formatting = Formatting.Indented
            };
        }

        public IDistributedMessage Deserialize(Stream data)
        {
            using var reader = new StreamReader(data);
            var text = reader.ReadToEnd();
            var envelope = JsonConvert.DeserializeObject(text, _serializationSettings) as JObject;
            if (envelope == null)
                throw new InvalidDataException("Deserialization error.");

            var typeName = envelope["Type"]?.ToString();
            if (typeName == null)
                throw new InvalidDataException("TypeName not found.");

            if (!_knownMessageTypes.TryGetValue(typeName, out var type))
                throw new InvalidDataException("Type not found: " + typeName);

            var msg = envelope["Msg"];
            if (msg == null)
                throw new InvalidDataException("Message not found");

            var message = msg.ToObject(type, JsonSerializer.Create(_serializationSettings));
            if (message == null)
                throw new InvalidDataException($"Conversion to {typeName} is failed.");

            var result = message as IDistributedMessage;
            if (result == null)
                throw new InvalidDataException("Conversion to ClusterMessage is failed.");

            return result;
        }

        public Stream Serialize(IDistributedMessage message)
        {
            var envelope = new Envelope { Type = message.GetType().FullName, Msg = message };
            var text = JsonConvert.SerializeObject(envelope, _serializationSettings);
            var stream = GetStreamFromString(text);
            return stream;
        }

        private static MemoryStream GetStreamFromString(string textData)
        {
            var stream = new MemoryStream();

            // Write to the stream only if the text is not empty, because writing an empty
            // string in UTF-8 format would result in a 3 bytes length stream.
            if (!string.IsNullOrEmpty(textData))
            {
                var writer = new StreamWriter(stream, Encoding.UTF8);
                writer.Write(textData);
                writer.Flush();

                stream.Position = 0;
            }

            return stream;
        }
    }
}
