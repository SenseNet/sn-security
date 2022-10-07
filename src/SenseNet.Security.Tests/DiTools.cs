using Microsoft.Extensions.Options;
using SenseNet.Security.Messaging;

namespace SenseNet.Security.Tests
{
    public class DiTools
    {
        public static IMessageProvider CreateDefaultMessageProvider(string computerId = null, string instanceId = null)
        {
            return new DefaultMessageProvider(CreateMessageSenderManager(computerId, instanceId));
        }
        public static IMessageSenderManager CreateMessageSenderManager(string computerId = null, string instanceId = null)
        {
            return new MessageSenderManager(
                new OptionsWrapper<MessageSenderOptions>(
                    new MessageSenderOptions { ComputerId = computerId, InstanceId = instanceId }));
        }
    }
}
