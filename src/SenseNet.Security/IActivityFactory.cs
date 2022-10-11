using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using SenseNet.Diagnostics;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security
{
    public interface IActivitySerializer
    {
        byte[] SerializeActivity(SecurityActivity activity);
        SecurityActivity DeserializeActivity(byte[] bytes);
    }

    internal class ActivitySerializer : IActivitySerializer
    {
        private readonly SecuritySystem _securitySystem;
        private readonly ISecurityMessageFormatter _messageFormatter;

        //UNDONE:DI: Remove SecuritySystem dependency
        public ActivitySerializer(SecuritySystem securitySystem, ISecurityMessageFormatter messageFormatter)
        {
            _securitySystem = securitySystem;
            _messageFormatter = messageFormatter;
        }

        public byte[] SerializeActivity(SecurityActivity activity)
        {
            var stream = _messageFormatter.Serialize(activity);
            if (stream is MemoryStream memoryStream)
                return memoryStream.GetBuffer();
            var buffer = new byte[stream.Length];
            stream.Position = 0;
            stream.Read(buffer, 0, buffer.Length);
            return buffer;

        }

        public SecurityActivity DeserializeActivity(byte[] bytes)
        {
            var activity = (SecurityActivity)_messageFormatter.Deserialize(new MemoryStream(bytes));
            //UNDONE:DI: Remove SecuritySystem dependency: add GeneralSecurityContext to the services
            activity.Context = _securitySystem.GeneralSecurityContext;
            return activity;
        }
    }
}
