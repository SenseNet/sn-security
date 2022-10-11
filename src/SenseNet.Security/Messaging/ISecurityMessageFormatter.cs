using System.IO;

namespace SenseNet.Security.Messaging
{
    public interface ISecurityMessageFormatter
    {
        IDistributedMessage Deserialize(Stream data);
        public Stream Serialize(IDistributedMessage message);
    }
}