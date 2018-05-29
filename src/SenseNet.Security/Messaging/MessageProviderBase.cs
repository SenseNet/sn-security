using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading;
using SenseNet.Diagnostics;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// A built-in message provider implementation that is able to put masseges into
    /// a pipeline and process them simultaniously on a configurable number of threads.
    /// </summary>
    public abstract class MessageProviderBase : IMessageProvider
    {
        private readonly object _messageListSwitchSync = new object();
        private List<IDistributedMessage> _incomingMessages = new List<IDistributedMessage>();
        private int _incomingMessageCount;
        private bool _allowMessageProcessing;
        private DateTime _startingTheSystem = DateTime.MaxValue;

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

        /// <inheritdoc />
        public virtual void Initialize()
        {
            _incomingMessages = new List<IDistributedMessage>();

            // initiate processing threads
            for (var i = 0; i < Configuration.Messaging.MessageProcessorThreadCount; i++)
            {
                var thstart = new ParameterizedThreadStart(CheckProcessableMessages);
                var thread = new Thread(thstart) { Name = i.ToString() };
                thread.Start();
            }
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
                return;
            if (message.Sender.IsMe)
            {
                SnTrace.Messaging.Write($"{message.GetType().Name} SKIPPED as local (from me).");
                return;
            }

            if (message.MessageSent < _startingTheSystem)
            {
                SnTrace.Messaging.Write($"{message.GetType().Name} was sent before system startup ({message.MessageSent}), it is SKIPPED.");
                return;
            }

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

                if (_incomingMessageCount <= Configuration.Messaging.MessageProcessorThreadMaxMessages)
                {
                    // if total message count is smaller than the maximum allowed, process all of them and empty incoming queue
                    messagesToProcess = _incomingMessages;
                    _incomingMessages = new List<IDistributedMessage>();
                }
                else
                {
                    // process the maximum allowed number of messages, leave the rest in the incoming queue
                    messagesToProcess = _incomingMessages.Take(Configuration.Messaging.MessageProcessorThreadMaxMessages).ToList();
                    _incomingMessages = _incomingMessages.Skip(Configuration.Messaging.MessageProcessorThreadMaxMessages).ToList();
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
                        List<IDistributedMessage> messagesToProcess;
                        while ((messagesToProcess = GetProcessableMessages()) != null)
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
                    SnLog.WriteException(ex, EventMessage.Error.MessageProcessing, EventId.Messaging);
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
            var bf = new BinaryFormatter();
            IDistributedMessage message;
            try
            {
                message = (IDistributedMessage)bf.Deserialize(data);
            }
            catch (SerializationException e) //logged
            {
                SnLog.WriteException(e, EventMessage.Error.MessageDeserialization, EventId.Messaging);
                message = new UnknownMessage { MessageData = data };
                // don't rethrow because caller handles
            }
            return message;
        }
        /// <summary>
        /// Helper method for serializing a message object. The current implementation
        /// uses BinaryFormatter for this purpose.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        protected virtual Stream SerializeMessage(object message)
        {
            try
            {
                var ms = new MemoryStream();
                var bf = new BinaryFormatter();
                bf.Serialize(ms, message);
                ms.Flush();
                ms.Position = 0;
                return ms;
            }
            catch (Exception e)
            {
                SnLog.WriteException(e, EventMessage.Error.MessageSerialization, EventId.Messaging);
                throw;
            }
        }
    }
}
