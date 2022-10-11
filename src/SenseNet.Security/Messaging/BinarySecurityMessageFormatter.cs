using SenseNet.Diagnostics;
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;

namespace SenseNet.Security.Messaging
{
    public class BinarySecurityMessageFormatter : ISecurityMessageFormatter
    {
        public IDistributedMessage Deserialize(Stream data)
        {
            var bf = new BinaryFormatter();
            IDistributedMessage message;
            try
            {
                message = (IDistributedMessage)bf.Deserialize(data);
            }
            catch (SerializationException e) //logged
            {
                SnLog.WriteException(e, EventMessage.Error.MessageDeserialization, EventId.Messaging);
                message = new UnknownMessage { MessageData = data };
                // don't rethrow because caller handles
            }
            return message;
        }

        public Stream Serialize(IDistributedMessage message)
        {
            try
            {
                var ms = new MemoryStream();
                var bf = new BinaryFormatter();
                bf.Serialize(ms, message);
                ms.Flush();
                ms.Position = 0;
                return ms;
            }
            catch (Exception e)
            {
                SnLog.WriteException(e, EventMessage.Error.MessageSerialization, EventId.Messaging);
                throw;
            }

        }
    }
}
