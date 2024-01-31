using SenseNet.Tools.Configuration;

// ReSharper disable once CheckNamespace
namespace SenseNet.Security.Messaging.RabbitMQ;

[OptionsClass(sectionName: "sensenet:security:rabbitmq")]
public class RabbitMqOptions
{
    public string ServiceUrl { get; set; } = "amqp://localhost:5672";
    public string MessageExchange { get; set; } = "snsecurity";
}