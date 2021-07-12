using System;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Describes an interface for sending and receiving messages among AppDomains.
    /// </summary>
    public interface IMessageProvider
    {
        /// <summary>
        /// Gets the name of the receiver (or channel)
        /// </summary>
        string ReceiverName { get; }
        /// <summary>
        /// Gets a total count of received messages
        /// </summary>
        int IncomingMessageCount { get; }
        /// <summary>
        /// Manages the <see cref="IMessageSender"/> objects.
        /// </summary>
        IMessageSenderManager MessageSenderManager { get; }
        /// <summary>
        /// Initializes the provider instance.
        /// </summary>
        void Initialize();
        /// <summary>
        /// Sends the passed message to all other AppDomains.
        /// </summary>
        void SendMessage(IDistributedMessage message);

        /// <summary>
        /// Starts sending and receiving messages. This is the first call that is in the system startup sequence.
        /// </summary>
        void Start(DateTime startingTheSystem);
        /// <summary>
        /// Starts sending and receiving messages after stop.
        /// </summary>
        void Start();
        /// <summary>
        /// Stops sending and receiving messages.
        /// </summary>
        // ReSharper disable once UnusedMemberInSuper.Global
        void Stop();
        /// <summary>
        /// Clears all messages that are not sent (if there are).
        /// </summary>
        void Purge();
        /// <summary>
        /// Shuts down the component.
        /// </summary>
        void ShutDown();

        /// <summary>
        /// Occurs when a message received
        /// </summary>
        event MessageReceivedEventHandler MessageReceived;
        /// <summary>
        /// Occurs when an error occured during receiving a message.
        /// </summary>
        event ReceiveExceptionEventHandler ReceiveException;
        /// <summary>
        /// Occurs when an error occured during sending a message.
        /// </summary>
        event SendExceptionEventHandler SendException;
    }

    /// <summary>
    /// Fired when a receiver gets a message.
    /// </summary>
    public delegate void MessageReceivedEventHandler(object sender, MessageReceivedEventArgs args);
    /// <summary>
    /// Fired when a receiver catches an exception.
    /// </summary>
    public delegate void ReceiveExceptionEventHandler(object sender, ExceptionEventArgs args);
    /// <summary>
    /// Fired when a message sender catches an exception.
    /// </summary>
    public delegate void SendExceptionEventHandler(object sender, ExceptionEventArgs args);

    /// <summary>
    /// Used in the MessageReceivedEventHandler. Contains the received message.
    /// </summary>
    public class MessageReceivedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets or sets the received message.
        /// </summary>
        public IDistributedMessage Message { get; set; }
        /// <summary>
        /// Initializes a new instance of the MessageReceivedEventArgs
        /// </summary>
        public MessageReceivedEventArgs(IDistributedMessage message) { Message = message; }
    }
    /// <summary>
    /// Used in the SendExceptionEventHandler and the ReceiveExceptionEventHandler. Contains the message and the exception.
    /// </summary>
    public class ExceptionEventArgs : EventArgs
    {
        /// <summary>
        /// Gets or sets the caught exception.
        /// </summary>
        public Exception Exception { get; set; }
        /// <summary>
        /// Gets or sets the message that was tried to send.
        /// </summary>
        public IDistributedMessage Message { get; set; }
        /// <summary>
        /// Initializes a new instance of the ExceptionEventArgs
        /// </summary>
        public ExceptionEventArgs(Exception exception, IDistributedMessage message)
        {
            Exception = exception;
            Message = message;
        }
    }

}
