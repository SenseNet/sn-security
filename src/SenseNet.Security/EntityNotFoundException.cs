using System;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents an error that occurs when an existence of an entity is expected but it is not found.
    /// </summary>
    [Serializable]
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    public class EntityNotFoundException : SecurityStructureException
    {
        /// <summary>Initializes a new instance of the EntityNotFoundException class.</summary>
        public EntityNotFoundException() { }
        /// <summary>Initializes a new instance of the EntityNotFoundException class.</summary>
        public EntityNotFoundException(string message) : base(message) { }
        /// <summary>Initializes a new instance of the EntityNotFoundException class.</summary>
        public EntityNotFoundException(string message, Exception inner) : base(message, inner) { }
        /// <summary>Initializes a new instance of the EntityNotFoundException class with serialized data.</summary>
        protected EntityNotFoundException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }
}
