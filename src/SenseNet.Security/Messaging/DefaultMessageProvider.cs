using System;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Default implementation of the IMessageProvider.
    /// Does nothing, it is absolutely inactive.
    /// </summary>
    public class DefaultMessageProvider : IMessageProvider
    {
        /// <summary>
        /// Gets the name of the receiver (or channel)
        /// </summary>
        public string ReceiverName => AppDomain.CurrentDomain.FriendlyName;

        /// <summary>
        /// Gets a total count of received messages
        /// </summary>
        public int IncomingMessageCount => 0;

        /// <summary>
        /// Initializes the provider instance.
        /// </summary>
        public void Initialize() { }
        /// <summary>
        /// Sends the passed message to all other AppDomains.
        /// </summary>
        public void SendMessage(IDistributedMessage message) { /* do nothing */ }
        /// <summary>
        /// Starts sending and receiving messages. This is the first call that is in the system startup sequence.
        /// </summary>
        public void Start(DateTime startingTheSystem) { /* do nothing */ }
        /// <summary>
        /// Starts sending and receiving messages after stop.
        /// </summary>
        public void Start() { /* do nothing */ }
        /// <summary>
        /// Stops sending and receiving messages.
        /// </summary>
        public void Stop() { /* do nothing */ }
        /// <summary>
        /// Clears all messages that were not sent.
        /// </summary>
        public void Purge() { /* do nothing */ }
        /// <summary>
        /// Shuts down the component.
        /// </summary>
        public void ShutDown() { /* do nothing */ }

        #pragma warning disable 0067
        /// <summary>
        /// Fired when a receiver gets a message.
        /// </summary>
        public event MessageReceivedEventHandler MessageReceived;
        /// <summary>
        /// Fired when a receiver catches an exception.
        /// </summary>
        public event ReceiveExceptionEventHandler ReceiveException;
        /// <summary>
        /// Fired when a message sender catches an exception.
        /// </summary>
        public event SendExceptionEventHandler SendException;
        #pragma warning restore
    }
}
