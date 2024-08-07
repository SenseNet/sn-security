﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using SenseNet.Diagnostics;
using SenseNet.Security.Configuration;
using EventId = SenseNet.Diagnostics.EventId;

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
        private IModel ReceiverChannel { get; set; }

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
        public override void Initialize()
        {
            if (_initialized)
                return;

            base.Initialize();

            try
            {
                Connection = OpenConnection(ServiceUrl);
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
                using (var initChannel = OpenChannel(Connection))
                {
                    initChannel.ExchangeDeclare(MessageExchange, "fanout");

                    // let the server generate a unique queue name
                    queueName = initChannel.QueueDeclare().QueueName;
                    SnTrace.Messaging.Write($"RMQ: RabbitMQ Security queue declared: {queueName}");

                    initChannel.QueueBind(queueName, MessageExchange, string.Empty);

                    SnTrace.Messaging.Write($"RMQ: RabbitMQ Security queue {queueName} is bound to exchange {MessageExchange}.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RabbitMQ Security message provider connection error. Service url: {ServiceUrl}", ServiceUrl);
                throw;
            }

            // use a single channel for receiving messages
            ReceiverChannel = OpenChannel(Connection);

            var consumer = new EventingBasicConsumer(ReceiverChannel);
            consumer.Shutdown += (sender, args) => { SnTrace.Messaging.Write("RMQ: RabbitMQ Security consumer shutdown."); };
            consumer.ConsumerCancelled += (sender, args) => { SnTrace.Messaging.Write("RMQ: RabbitMQ Security consumer cancelled."); };
            consumer.Received += (model, args) =>
            {
                // this is the main entry point for receiving messages
                using (var ms = new MemoryStream(args.Body.ToArray()))
                {
                    OnMessageReceived(ms);
                }
            };

            ReceiverChannel.BasicConsume(queueName, true, consumer);

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

                    using (var channel = OpenChannel(Connection))
                    {
                        channel.BasicPublish(MessageExchange, string.Empty, null, body);
                        channel.Close();
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
            ReceiverChannel?.Close();
            Connection?.Close();

            base.ShutDown();

            _initialized = false;
        }

        //=================================================================================== Helper methods

        private static IModel OpenChannel(IConnection connection)
        {
            var channel = connection.CreateModel();
            channel.CallbackException += (sender, args) =>
            {
                SnLog.WriteException(args.Exception);
                SnTrace.Messaging.WriteError($"RMQ: RabbitMQ Security channel callback exception: {args.Exception?.Message}");
            };

            return channel;
        }
        private static IConnection OpenConnection(string serviceUrl)
        {
            var factory = new ConnectionFactory { Uri = new Uri(serviceUrl) };
            var connection = factory.CreateConnection();
            connection.CallbackException += (sender, ea) =>
            {
                SnLog.WriteException(ea.Exception);
                SnTrace.Messaging.WriteError($"RMQ: RabbitMQ Security connection callback exception: {ea.Exception?.Message}");
            };
            connection.ConnectionShutdown += (sender, ea) =>
            {
                SnTrace.Messaging.Write("RMQ: RabbitMQ Security connection shutdown.");
            };

            return connection;
        }
    }
}
