using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using SenseNet.Diagnostics;
using SenseNet.Security.Configuration;

namespace SenseNet.Security.Messaging.RabbitMQ
{
    // ReSharper disable once InconsistentNaming
    /// <summary>
    /// IMessageProvider implementation over RabbitMQ.
    /// </summary>
    public class RabbitMQMessageProvider : MessageProviderBase
    {
        private readonly ILogger<RabbitMQMessageProvider> _logger;
        private bool _initialized;

        /// <summary>
        /// RabbitMQ service url.
        /// </summary>
        protected string ServiceUrl { get; }
        /// <summary>
        /// Optional exchange name. Mandatory in case the same service is used 
        /// by multiple different environments (e.g. test and live environment).
        /// </summary>
        protected string MessageExchange { get; }

        //=================================================================================== Constructors

        /// <summary>
        /// Initializes a new instance of the RabbitMQMessageProvider class with default parameters.
        /// </summary>
        /// <param name="messageSenderManager">Required IMessageSenderManager instance.</param>
        /// <param name="messageFormatter"></param>
        /// <param name="messagingOptions"></param>
        /// <param name="rabbitmqOptions"></param>
        /// <param name="logger"></param>
        public RabbitMQMessageProvider(IMessageSenderManager messageSenderManager,
            ISecurityMessageFormatter messageFormatter,
            IOptions<MessagingOptions> messagingOptions,
            IOptions<RabbitMqOptions> rabbitmqOptions,
            ILogger<RabbitMQMessageProvider> logger) :
            base(messageSenderManager, messageFormatter, messagingOptions, logger)
        {
            _logger = logger;
            ServiceUrl = rabbitmqOptions.Value.ServiceUrl;
            MessageExchange = rabbitmqOptions.Value.MessageExchange;
        }

        //=================================================================================== Shared resources

        private IConnection Connection { get; set; }
        private IChannel ReceiverChannel { get; set; }

        //=================================================================================== Overrides

        /// <summary>
        /// Returns the 'RabbitMQ' constant.
        /// </summary>
        public override string ReceiverName => "RabbitMQ";

        /// <summary>
        /// Initializes a RabbitMQ service connection based on the provided service url.
        /// Declares the exchange and binds a consumer queue.
        /// Opens a receiver channel and creates a consumer for receiving messages.
        /// </summary>
        public override async Task InitializeAsync(CancellationToken cancel)
        {
            if (_initialized)
                return;

            await base.InitializeAsync(cancel);

            try
            {
                Connection = await OpenConnectionAsync(ServiceUrl, cancel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Connection could not be established to service {ServiceUrl}. Error: {ex.Message}");
                return;
            }
            
            string queueName;

            try
            {
                // declare an exchange and bind a queue unique for this application
                using (var initChannel = await OpenChannelAsync(Connection, cancel))
                {
                    await initChannel.ExchangeDeclareAsync(MessageExchange, "fanout", cancellationToken: cancel);

                    // let the server generate a unique queue name
                    queueName = (await initChannel.QueueDeclareAsync(cancellationToken: cancel)).QueueName;
                    SnTrace.Messaging.Write($"RMQ: RabbitMQ Security queue declared: {queueName}");

                    await initChannel.QueueBindAsync(queueName, MessageExchange, string.Empty, cancellationToken: cancel);

                    SnTrace.Messaging.Write($"RMQ: RabbitMQ Security queue {queueName} is bound to exchange {MessageExchange}.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RabbitMQ Security message provider connection error. Service url: {ServiceUrl}", ServiceUrl);
                throw;
            }

            // use a single channel for receiving messages
            ReceiverChannel = await OpenChannelAsync(Connection, cancel);

            var consumer = new AsyncEventingBasicConsumer(ReceiverChannel);
            consumer.ShutdownAsync += (_, args) =>
            {
                SnTrace.Messaging.Write("RMQ: RabbitMQ Security consumer shutdown.");
                return Task.CompletedTask;
            };
            consumer.ReceivedAsync += async (_, args) =>
            {
                var messageLength = args?.Body.Length ?? 0;
                SnTrace.Messaging.Write($"RMQ: Message received. Length: {messageLength}");
                if (messageLength == 0)
                    return;

                // this is the main entry point for receiving messages
                var body = args.Body.ToArray();
                using var ms = new MemoryStream(body);
                OnMessageReceived(ms);
            };

            await ReceiverChannel.BasicConsumeAsync(queueName, true, consumer, cancellationToken: cancel);

            _logger.LogInformation("RabbitMQ Security message provider connected to {ServiceUrl} " +
                                   "through exchange {Exchange} and queue {QueueName}", 
                ServiceUrl, MessageExchange, queueName);

            _initialized = true;
        }

        /// <summary>
        /// Serializes a message, opens a channel and publishes the message asynchronously.
        /// </summary>
        public override void SendMessage(IDistributedMessage message)
        {
            if (message == null)
            {
                SnTrace.Messaging.WriteError("RMQ: Security: Empty message.");
                return;
            }
            
            // This has to be set before sending the message so that receivers
            // can decide whether they should process it or not.
            message.MessageSent = DateTime.UtcNow;

            byte[] body;

            try
            {
                _logger.LogTrace($"Serializing security message {message.GetType().Name}");

                using (var messageStream = SerializeMessage(message))
                {
                    if (messageStream is MemoryStream ms)
                    {
                        body = ms.ToArray();
                    }
                    else
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            messageStream?.CopyTo(memoryStream);
                            body = memoryStream.ToArray();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during security message serialization. Message type: {MessageType}", 
                    message.GetType().Name);

                return;
            }

            Task.Run(() =>
            {
                // Create a channel per send request to avoid sharing channels 
                // between threads and be able to dispose the object.
                try
                {
                    _logger.LogTrace($"Sending security message {message.GetType().Name}");

                    using (var channel = OpenChannelAsync(Connection, CancellationToken.None).GetAwaiter().GetResult())
                    {
                        channel.BasicPublishAsync(MessageExchange, string.Empty, body, CancellationToken.None)
                            .GetAwaiter().GetResult();
                        channel.CloseAsync(CancellationToken.None).GetAwaiter().GetResult();
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Security message SEND ERROR");
                    SnTrace.Messaging.WriteError($"Security message SEND ERROR {ex.Message}");

                    OnSendException(message, ex);
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Shuts down the message provider and releases resources.
        /// </summary>
        public override void ShutDown()
        {
            ReceiverChannel?.CloseAsync().GetAwaiter().GetResult();
            Connection?.CloseAsync().GetAwaiter().GetResult();

            base.ShutDown();

            _initialized = false;
        }

        //=================================================================================== Helper methods

        private async Task<IChannel> OpenChannelAsync(IConnection connection, CancellationToken cancel)
        {
            var channel = await connection.CreateChannelAsync(cancellationToken: cancel);
            channel.CallbackExceptionAsync += (sender, args) =>
            {
                SnLog.WriteException(args.Exception);
                SnTrace.Messaging.WriteError($"RMQ: RabbitMQ Security channel callback exception: {args.Exception?.Message}");
                return Task.CompletedTask;
            };

            return channel;
        }
        private static async Task<IConnection> OpenConnectionAsync(string serviceUrl, CancellationToken cancel)
        {
            var factory = new ConnectionFactory { Uri = new Uri(serviceUrl), ConsumerDispatchConcurrency = 5 };
            var connection = await factory.CreateConnectionAsync(cancel);
            connection.CallbackExceptionAsync += (_, ea) =>
            {
                SnLog.WriteException(ea.Exception);
                SnTrace.Messaging.WriteError($"RMQ: RabbitMQ Security connection callback exception: {ea.Exception?.Message}");
                return Task.CompletedTask;
            };
            connection.ConnectionShutdownAsync += (_, ea) =>
            {
                SnTrace.Messaging.Write("RMQ: RabbitMQ Security connection shutdown.");
                return Task.CompletedTask;
            };

            return connection;
        }
    }
}
