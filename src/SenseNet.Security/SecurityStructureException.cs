using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents an error that occurs when there is a mistake in connection with
    /// creating, updating or deleting entities or entries.
    /// </summary>
    [Serializable]
    [ExcludeFromCodeCoverage]
    public class SecurityStructureException : Exception
    {
        /// <summary>Initializes a new instance of the SecurityStructureException class.</summary>
        public SecurityStructureException() { }
        /// <summary>Initializes a new instance of the SecurityStructureException class.</summary>
        public SecurityStructureException(string message) : base(message) { }
        /// <summary>Initializes a new instance of the SecurityStructureException class.</summary>
        public SecurityStructureException(string message, Exception inner) : base(message, inner) { }
        /// <summary>Initializes a new instance of the SecurityStructureException class with serialized data.</summary>
        protected SecurityStructureException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}
