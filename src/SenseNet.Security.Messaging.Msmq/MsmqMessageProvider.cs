using System;
using System.Collections.Generic;
using System.Linq;
using System.Messaging;
using System.Threading;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using SenseNet.Diagnostics;

namespace SenseNet.Security.Messaging.Msmq
{
    /// <summary>
    /// IMessageProvider implementation on top of MSMQ.
    /// </summary>
    internal sealed class MsmqMessageProvider : IMessageProvider
    {
        private MessageQueue _receiveQueue;
        private List<MessageQueue> _sendQueues;
        private List<bool> _sendQueuesAvailable;
        private readonly ReaderWriterLockSlim _senderLock = new ReaderWriterLockSlim();
        private readonly BinaryMessageFormatter _formatter = new BinaryMessageFormatter();
        private bool _allowMessageProcessing;
        private static bool _shutdown;

        public string ReceiverName => _receiveQueue.Path;


        /* ============================================================================== Events */
        public event MessageReceivedEventHandler MessageReceived;
        public event ReceiveExceptionEventHandler ReceiveException;
        public event SendExceptionEventHandler SendException;


        /* ============================================================================== Initialization */
        public void Initialize()
        {
            _incomingMessages = new List<IDistributedMessage>();

            // initiate processing threads
            for (var i = 0; i < Configuration.MessageProcessorThreadCount; i++)
            {
                var thstart = new ParameterizedThreadStart(CheckProcessableMessages);
                var thread = new Thread(thstart) {Name = i.ToString()};
                thread.Start();
            }

            BuildQueues();
        }
        private void BuildQueues()
        {
            var queuepaths = Configuration.MessageQueueName.Split(';');
            if (queuepaths.Length < 2)
                throw new Exception("No queues have been initialized. Please verify you have provided at least 2 queue paths: first for local, the rest for remote queues!");

            _receiveQueue = CreateQueue(queuepaths[0]);
            var receiverThread = new Thread(ReceiveMessages);
            receiverThread.Start();

            _sendQueues = new List<MessageQueue>();
            _sendQueuesAvailable = new List<bool>();
            foreach (var queuepath in queuepaths.Skip(1))
            {
                var sendQueue = CreateQueue(queuepath);
                _sendQueues.Add(sendQueue);
                _sendQueuesAvailable.Add(true);
            }
        }
        private MessageQueue CreateQueue(string queuepath)
        {
            return new MessageQueue(queuepath) {Formatter = new BinaryMessageFormatter()};
        }

        private MessageQueue RecoverQueue(MessageQueue queue)
        {
            // the queue must be closed and the connection cache cleared before we try to reconnect
            queue.Close();
            MessageQueue.ClearConnectionCache();

            Thread.Sleep(Configuration.MsmqReconnectDelay);

            // reconnect
            return CreateQueue(queue.Path);
        }


        /* ============================================================================== Controlling */
        private DateTime _startingTheSystem = DateTime.MaxValue;
        public void Start(DateTime startingTheSystem)
        {
            _startingTheSystem = startingTheSystem;
            Start();
        }
        public void Start()
        {
            _allowMessageProcessing = true;
        }
        public void Stop()
        {
            _allowMessageProcessing = false;
        }
        public void Purge()
        {
            var iterator = _receiveQueue.GetMessageEnumerator2();
            while (iterator.MoveNext()) { }

            _receiveQueue.Purge();
        }
        public void ShutDown()
        {
            Stop();
            _shutdown = true;
        }


        /* ============================================================================== Send */
        public void SendMessage(IDistributedMessage message)
        {
            try
            {
                message.MessageSent = DateTime.UtcNow;
                Stream messageStream = SerializeMessage(message);
                InternalSend(messageStream);
            }
            catch (Exception e)
            {
                SnLog.WriteException(e, EventMessage.Errors.SendError, EventId.Messaging);
                OnSendException(message, e);
            }
        }
        private void InternalSend(Stream messageBody)
        {
            var message = new Message(messageBody)
            {
                TimeToBeReceived = TimeSpan.FromSeconds(Configuration.MessageRetentionTime),
                Formatter = _formatter
            };

            // try to send message to all queues. we enter read lock, since another thread could paralelly repair any of the queues
            bool success;
            _senderLock.EnterReadLock();
            try
            {
                success = SendToAllQueues(message);
            }
            finally
            {
                _senderLock.ExitReadLock();
            }

            // check if any of the queues needs to be restarted
            if (!success)
            {
                // enter write lock, so no send will occur
                _senderLock.EnterWriteLock();
                try
                {
                    RepairSendQueues();
                }
                finally
                {
                    _senderLock.ExitWriteLock();
                }
            }
        }
        private bool SendToAllQueues(Message message)
        {
            var success = true;
            for (var i = 0; i < _sendQueues.Count; i++)
            {
                // if a sender queue is not available at the moment due to a previous error, don't send the message
                if (!_sendQueuesAvailable[i])
                    continue;

                try
                {
                    _sendQueues[i].Send(message);
                }
                catch (MessageQueueException mex)
                {
                    SnLog.WriteException(mex, EventMessage.Errors.SendError, EventId.Messaging);
                    _sendQueuesAvailable[i] = false;    // indicate that the queue is out of order
                    success = false;
                }
                catch (Exception ex)
                {
                    SnLog.WriteException(ex, EventMessage.Errors.SendError, EventId.Messaging);
                    _sendQueuesAvailable[i] = false;    // indicate that the queue is out of order
                    success = false;
                }
            }
            return success;
        }
        private void RepairSendQueues()
        {
            bool repairHappened = false;
            for (var i = 0; i < _sendQueues.Count; i++)
            {
                if (!_sendQueuesAvailable[i])
                {
                    try
                    {
                        _sendQueues[i] = RecoverQueue(_sendQueues[i]);
                        _sendQueuesAvailable[i] = true;     // indicate that the queue is up and running
                        repairHappened = true;
                    }
                    catch (Exception ex)
                    {
                        SnLog.WriteException(ex, EventMessage.Errors.RepairError, EventId.Messaging);
                    }
                }
            }
            if (repairHappened)
            {
                SnLog.WriteInformation("Send queues have been repaired.", EventId.Messaging);
            }
        }


        /* ============================================================================== Receive */
        private int _incomingMessageCount;
        /// <summary>
        /// Returns the count of unprocessed incoming messages. Slowing down the producing of messages maybe necessary if it exceeds a certain amount.
        /// </summary>
        public int IncomingMessageCount => _incomingMessageCount;

        private static volatile int _messagesCount;
        private static readonly object _messageListSwitchSync = new object();
        private static List<IDistributedMessage> _incomingMessages;

        private void ReceiveMessages()
        {
            while (true)
            {
                try
                {
                    var message = _receiveQueue.Receive(TimeSpan.FromSeconds(1));
                    if(message==null)
                        return;

                    if (_shutdown)
                        return;

                    OnMessageReceived(message.Body as Stream);
                }
                catch (ThreadAbortException tex)
                {
                    // suppress threadabortexception on shutdown
                    if (_shutdown)
                        return;

                    SnLog.WriteException(tex, $"An error occurred when receiving from the queue ({_receiveQueue.Path}).",
                        EventId.Messaging);
                }
                catch (MessageQueueException mex)
                {
                    // check if receive timed out: this is not a problem
                    if (mex.MessageQueueErrorCode == MessageQueueErrorCode.IOTimeout)
                    {
                        if (_shutdown)
                            return;
                        continue;
                    }

                    SnLog.WriteException(mex, $"An error occurred when receiving from the queue ({_receiveQueue.Path}).",
                        EventId.Messaging);
                    OnReceiveException(mex);

                    try
                    {
                        _receiveQueue = RecoverQueue(_receiveQueue);
                        SnLog.WriteInformation("Receiver queue has been repaired.", EventId.Messaging);
                    }
                    catch (Exception ex)
                    {
                        SnLog.WriteException(ex, EventMessage.Errors.RepairError, EventId.Messaging);
                    }
                    var thread = new Thread(ReceiveMessages);
                    thread.Start();
                    return;
                }
                catch (Exception e)
                {
                    SnLog.WriteException(e, $"An error occurred when receiving from the queue ({_receiveQueue.Path}).",
                        EventId.Messaging);
                    OnReceiveException(e);
                }
            }
        }
        private void OnMessageReceived(Stream messageBody)
        {
            var message = DeserializeMessage(messageBody);
            if (message == null)
                return;
            if (message.Sender.IsMe)
                return;

            if (message.MessageSent < _startingTheSystem)
                return;

            lock (_messageListSwitchSync)
                _incomingMessages.Add(message);
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
#pragma warning disable 0420
                            Interlocked.Add(ref _messagesCount, count);
#pragma warning restore 0420

                            // process all messages in the queue
                            for (var i = 0; i < count; i++)
                            {
                                ProcessSingleMessage(messagesToProcess[i]);
                                messagesToProcess[i] = null;
                            }

#pragma warning disable 0420
                            Interlocked.Add(ref _messagesCount, -count);
#pragma warning restore 0420

                            if (_shutdown)
                                return;
                        }
                    }
                }
                catch (Exception ex)
                {
                    SnLog.WriteException(ex, EventMessage.Errors.ProcessingError, EventId.Messaging);
                }

                // no messages to process, wait some time and continue checking incoming messages
                Thread.Sleep(100);

                if (_shutdown)
                    return;
            }
        }
        private List<IDistributedMessage> GetProcessableMessages()
        {
            List<IDistributedMessage> messagesToProcess;
            lock (_messageListSwitchSync)
            {
                _incomingMessageCount = _incomingMessages.Count;

                if (_incomingMessageCount == 0)
                    return null;

                if (_incomingMessageCount <= Configuration.MessageProcessorThreadMaxMessages)
                {
                    // if total message count is smaller than the maximum allowed, process all of them and empty incoming queue
                    messagesToProcess = _incomingMessages;
                    _incomingMessages = new List<IDistributedMessage>();
                }
                else
                {
                    // process the maximum allowed number of messages, leave the rest in the incoming queue
                    messagesToProcess = _incomingMessages.Take(Configuration.MessageProcessorThreadMaxMessages).ToList();
                    _incomingMessages = _incomingMessages.Skip(Configuration.MessageProcessorThreadMaxMessages).ToList();
                }
            }

            return messagesToProcess;
        }
        private void ProcessSingleMessage(object parameter)
        {
            var message = parameter as IDistributedMessage;
            MessageReceived?.Invoke(this, new MessageReceivedEventArgs(message));
        }


        /* ============================================================================== Error handling */
        private void OnSendException(IDistributedMessage message, Exception exception)
        {
            SendException?.Invoke(this, new ExceptionEventArgs(exception, message));
        }
        private void OnReceiveException(Exception exception)
        {
            ReceiveException?.Invoke(this, new ExceptionEventArgs(exception, null));
        }


        /* ============================================================================== Serialization */
        private IDistributedMessage DeserializeMessage(Stream data)
        {
            var bf = new BinaryFormatter();
            IDistributedMessage message;
            try
            {
                message = (IDistributedMessage)bf.Deserialize(data);
            }
            catch (SerializationException e) //logged
            {
                SnLog.WriteException(e, EventMessage.Errors.DeserializationError, EventId.Messaging);
                message = new UnknownMessage { MessageData = data };
                // don't rethrow because caller handles
            }
            return message;
        }
        private Stream SerializeMessage(object message)
        {
            try
            {
                MemoryStream ms = new MemoryStream();
                BinaryFormatter bf = new BinaryFormatter();
                bf.Serialize(ms, message);
                ms.Flush();
                ms.Position = 0;
                return ms;
            }
            catch (Exception e)
            {
                SnLog.WriteException(e, EventMessage.Errors.SerializationError, EventId.Messaging);
                throw;
            }
        }

    }
}
