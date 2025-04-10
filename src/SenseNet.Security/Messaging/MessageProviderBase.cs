﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SenseNet.Diagnostics;
using SenseNet.Security.Configuration;
using EventId = SenseNet.Diagnostics.EventId;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// A built-in message provider implementation that is able to put messages into
    /// a pipeline and process them simultaneously on a configurable number of threads.
    /// </summary>
    public abstract class MessageProviderBase : IMessageProvider
    {
        private readonly object _messageListSwitchSync = new object();
        private List<IDistributedMessage> _incomingMessages = new List<IDistributedMessage>();
        private int _incomingMessageCount;
        private bool _allowMessageProcessing;
        private DateTime _startingTheSystem = DateTime.MaxValue;
        private readonly MessagingOptions _options;

        private ISecurityMessageFormatter _messageFormatter;
        private readonly ILogger<MessageProviderBase> _logger;
        public IMessageSenderManager MessageSenderManager { get; }

        /// <summary>
        /// Gets or sets a value that tells the system whether the component has been shut down.
        /// </summary>
        protected bool Shutdown { get; set; }

        /// <inheritdoc />
        public abstract string ReceiverName { get; }
        /// <summary>
        /// Returns the count of unprocessed incoming messages. Slowing down the producing of messages maybe necessary if it exceeds a certain amount.
        /// </summary>
        public virtual int IncomingMessageCount => _incomingMessageCount;

        protected MessageProviderBase(
            IMessageSenderManager messageSenderManager,
            ISecurityMessageFormatter messageFormatter,
            IOptions<MessagingOptions> messagingOptions,
            ILogger<MessageProviderBase> logger)
        {
            MessageSenderManager = messageSenderManager;
            _messageFormatter = messageFormatter;
            _logger = logger;
            _options = messagingOptions.Value;
        }

        /// <inheritdoc />
        public virtual Task InitializeAsync(CancellationToken cancel)
        {
            _incomingMessages = new List<IDistributedMessage>();

            // initiate processing threads
            for (var i = 0; i < _options.MessageProcessorThreadCount; i++)
            {
                var thStart = new ParameterizedThreadStart(CheckProcessableMessages);
                var thread = new Thread(thStart) { Name = i.ToString() };
                thread.Start();
            }

            return Task.CompletedTask;
        }
        /// <inheritdoc />
        public abstract void SendMessage(IDistributedMessage message);

        /// <inheritdoc />
        public virtual void Start(DateTime startingTheSystem)
        {
            _startingTheSystem = startingTheSystem;

            Start();
        }
        /// <inheritdoc />
        public virtual void Start()
        {
            _allowMessageProcessing = true;
        }
        /// <inheritdoc />
        public virtual void Stop()
        {
            _allowMessageProcessing = false;
        }

        /// <inheritdoc />
        public virtual void Purge()
        {
            // inherited classes may delete incoming or outgoing messages here
        }
        /// <inheritdoc />
        public virtual void ShutDown()
        {
            Stop();
            Shutdown = true;
        }

        /// <summary>
        /// Called when a message arrives. This method has to deserialize the message
        /// and put in a worker queue where it will be picked up and executed.
        /// </summary>
        protected virtual void OnMessageReceived(Stream messageBody)
        {
            var message = DeserializeMessage(messageBody);
            if (message == null)
            {
                _logger.LogWarning("Security message received but could not be deserialized.");
                return;
            }

            if (MessageSenderManager.IsMe(message.Sender))
            {
                SnTrace.Messaging.Write($"{message.GetType().Name} SKIPPED as local (from me).");
                return;
            }

            if (message.MessageSent < _startingTheSystem)
            {
                SnTrace.Messaging.Write($"{message.GetType().Name} was sent before system startup ({message.MessageSent}), it is SKIPPED.");
                return;
            }

            _logger.LogTrace($"Security message {message.GetType().Name} received.");

            lock (_messageListSwitchSync)
                _incomingMessages.Add(message);
        }

        //============================================================================== Events

        /// <inheritdoc />
        public event MessageReceivedEventHandler MessageReceived;
        /// <inheritdoc />
        public event ReceiveExceptionEventHandler ReceiveException;
        /// <inheritdoc />
        public event SendExceptionEventHandler SendException;

        //============================================================================== Receive methods

        private List<IDistributedMessage> GetProcessableMessages()
        {
            List<IDistributedMessage> messagesToProcess;
            lock (_messageListSwitchSync)
            {
                _incomingMessageCount = _incomingMessages.Count;

                if (_incomingMessageCount == 0)
                    return null;

                if (_incomingMessageCount <= _options.MessageProcessorThreadMaxMessages)
                {
                    // if total message count is smaller than the maximum allowed, process all of them and empty incoming queue
                    messagesToProcess = _incomingMessages;
                    _incomingMessages = new List<IDistributedMessage>();
                }
                else
                {
                    // process the maximum allowed number of messages, leave the rest in the incoming queue
                    messagesToProcess = _incomingMessages.Take(_options.MessageProcessorThreadMaxMessages).ToList();
                    _incomingMessages = _incomingMessages.Skip(_options.MessageProcessorThreadMaxMessages).ToList();
                }
            }

            return messagesToProcess;
        }
        private void CheckProcessableMessages(object parameter)
        {
            while (true)
            {
                try
                {
                    if (_allowMessageProcessing)
                    {
                        while (GetProcessableMessages() is { } messagesToProcess)
                        {
                            var count = messagesToProcess.Count;

                            // process all messages in the queue
                            for (var i = 0; i < count; i++)
                            {
                                ProcessSingleMessage(messagesToProcess[i]);
                                messagesToProcess[i] = null;
                            }

                            if (Shutdown)
                                return;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, EventMessage.Error.MessageProcessing);
                }

                // no messages to process, wait some time and continue checking incoming messages
                Thread.Sleep(100);

                if (Shutdown)
                    return;
            }
        }
        private void ProcessSingleMessage(object parameter)
        {
            var message = parameter as IDistributedMessage;

            _logger.LogTrace($"Processing {message?.GetType().Name} security message.");

            MessageReceived?.Invoke(this, new MessageReceivedEventArgs(message));
        }

        //============================================================================== Error handling

        /// <summary>
        /// Derived classes may call this method when an exception occurs during sending a message.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="exception"></param>
        protected void OnSendException(IDistributedMessage message, Exception exception)
        {
            SendException?.Invoke(this, new ExceptionEventArgs(exception, message));
        }
        /// <summary>
        /// Derived classes may call this method when an exception occurs during receiving a message.
        /// </summary>
        protected void OnReceiveException(Exception exception)
        {
            ReceiveException?.Invoke(this, new ExceptionEventArgs(exception, null));
        }

        //============================================================================== Serialization

        /// <summary>
        /// Helper method for deserializing a message object. The current implementation
        /// uses BinaryFormatter for this purpose.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        protected virtual IDistributedMessage DeserializeMessage(Stream data)
        {
            try
            {
                return _messageFormatter.Deserialize(data);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deserializing security message. {ex.Message}");
            }

            return null;
        }
        /// <summary>
        /// Helper method for serializing a message object. The current implementation
        /// uses BinaryFormatter for this purpose.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        protected virtual Stream SerializeMessage(IDistributedMessage message)
        {
            return _messageFormatter.Serialize(message);
        }
    }
}
