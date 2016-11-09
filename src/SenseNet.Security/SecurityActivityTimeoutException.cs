using System;
using System.Runtime.Serialization;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents an error that occurs when a SecurityActivity execution times out.
    /// </summary>
    [Serializable]
    public class SecurityActivityTimeoutException : Exception
    {
        /// <summary>Initializes a new instance of the SecurityActivityTimeoutException class.</summary>
        public SecurityActivityTimeoutException() { }
        /// <summary>Initializes a new instance of the SecurityActivityTimeoutException class.</summary>
        public SecurityActivityTimeoutException(string message) : base(message) { }
        /// <summary>Initializes a new instance of the SecurityActivityTimeoutException class.</summary>
        public SecurityActivityTimeoutException(string message, Exception inner) : base(message, inner) { }
        /// <summary>Initializes a new instance of the SecurityActivityTimeoutException class with serialized data.</summary>
        protected SecurityActivityTimeoutException(
          SerializationInfo info,
          StreamingContext context)
            : base(info, context) { }
    }
}
