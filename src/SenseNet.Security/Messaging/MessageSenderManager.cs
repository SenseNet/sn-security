using System;
using Microsoft.Extensions.Options;

namespace SenseNet.Security.Messaging
{
    public class MessageSenderOptions
    {
        public string ComputerId { get; set; }
        public string InstanceId { get; set; }
    }
    public class MessageSenderManager : IMessageSenderManager
    {
        public MessageSenderManager(IOptions<MessageSenderOptions> messageSenderOptions)
        {
            var options = messageSenderOptions?.Value;
            ComputerId = options?.ComputerId ?? Environment.MachineName;
            InstanceId = options?.InstanceId ?? Guid.NewGuid().ToString();
        }

        public string ComputerId { get; }
        public string InstanceId { get; }

        public IMessageSender CreateMessageSender()
        {
            return new MessageSender(ComputerId, InstanceId);
        }

        public bool IsMe(IMessageSender sender)
        {
            return sender.InstanceID == InstanceId;
        }
    }
}
