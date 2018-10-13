using System;
using System.Collections.Generic;
using System.Text;

namespace SenseNet.Security
{
    /// <summary>
    /// Defines categories for Access Control Entry
    /// </summary>
    public enum EntryType
    {
        /// <summary>
        /// Category for general access control entry.
        /// </summary>
        Normal,
        /// <summary>
        /// Category for an access control entry that has further access rights by document-sharing.
        /// </summary>
        Sharing
    }
}
