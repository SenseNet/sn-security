using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using SenseNet.Diagnostics;
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

        public ActivitySerializer(SecuritySystem securitySystem)
        {
            _securitySystem = securitySystem;
        }

        public byte[] SerializeActivity(SecurityActivity activity)
        {
            try
            {
                var ms = new MemoryStream();
                var bf = new BinaryFormatter(); // 1 Save
                bf.Serialize(ms, activity);
                ms.Flush();
                ms.Position = 0;
                return ms.GetBuffer();
            }
            catch (Exception e) // logged and rethrown
            {
                SnLog.WriteException(e, EventMessage.Error.Serialization, EventId.Serialization);
                throw;
            }
        }

        public SecurityActivity DeserializeActivity(byte[] bytes)
        {
            Stream data = new MemoryStream(bytes);

            var bf = new BinaryFormatter(); // 3 Load
            SecurityActivity activity = null;
            try
            {
                activity = (SecurityActivity)bf.Deserialize(data);
                activity.Context = _securitySystem.GeneralSecurityContext;
            }
            catch (SerializationException e) // logged
            {
                SnLog.WriteException(e, EventMessage.Error.Deserialization, EventId.Serialization);
            }
            return activity;
        }
    }
}
