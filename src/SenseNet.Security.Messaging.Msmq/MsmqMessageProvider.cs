using System;
using System.Collections.Generic;
using System.Linq;
using System.Messaging;
using System.Threading;
using System.IO;
using SenseNet.Diagnostics;

namespace SenseNet.Security.Messaging.Msmq
{
    /// <summary>
    /// IMessageProvider implementation on top of MSMQ.
    /// </summary>
    internal sealed class MsmqMessageProvider : MessageProviderBase
    {
        private MessageQueue _receiveQueue;
        private List<MessageQueue> _sendQueues;
        private List<bool> _sendQueuesAvailable;
        private readonly ReaderWriterLockSlim _senderLock = new ReaderWriterLockSlim();
        private readonly BinaryMessageFormatter _formatter = new BinaryMessageFormatter();
        
        public override string ReceiverName => _receiveQueue.Path;

        /* ============================================================================== Initialization */
        public override void Initialize()
        {
            base.Initialize();

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
        
        public override void Purge()
        {
            var iterator = _receiveQueue.GetMessageEnumerator2();
            while (iterator.MoveNext()) { }

            _receiveQueue.Purge();
        }
        
        /* ============================================================================== Send */
        public override void SendMessage(IDistributedMessage message)
        {
            try
            {
                message.MessageSent = DateTime.UtcNow;
                var messageStream = SerializeMessage(message);
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
            var repairHappened = false;
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
        
        private void ReceiveMessages()
        {
            while (true)
            {
                try
                {
                    var message = _receiveQueue.Receive(TimeSpan.FromSeconds(1));
                    if(message==null)
                        return;

                    if (Shutdown)
                        return;

                    OnMessageReceived(message.Body as Stream);
                }
                catch (ThreadAbortException tex)
                {
                    // suppress threadabortexception on shutdown
                    if (Shutdown)
                        return;

                    SnLog.WriteException(tex, $"An error occurred when receiving from the queue ({_receiveQueue.Path}).",
                        EventId.Messaging);
                }
                catch (MessageQueueException mex)
                {
                    // check if receive timed out: this is not a problem
                    if (mex.MessageQueueErrorCode == MessageQueueErrorCode.IOTimeout)
                    {
                        if (Shutdown)
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
    }
}
