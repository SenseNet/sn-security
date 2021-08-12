namespace SenseNet.Security.Messaging.RabbitMQ
{
    public class RabbitMqOptions
    {
        public string ServiceUrl { get; set; } = "amqp://localhost:5672";
        public string MessageExchange { get; set; } = "snsecurity";
    }
}