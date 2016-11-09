using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SenseNet.Security.Tests.TestPortal
{
    internal class EventId
    {
        internal class Error
        {
            public const int SystemStart = 8001;
        }
    }
    internal class EventMessage
    {
        internal class Error
        {
            public const string SystemStart = "An error occured when starting the security system.";
        }
    }
}
