﻿namespace SenseNet.Security.Configuration
{
    internal static class Identities //UNDONE: Has static members (configuration)
    {
        public static int SystemUserId { get; internal set; }
        public static int VisitorUserId { get; internal set; }
        public static int EveryoneGroupId { get; internal set; }
        public static int OwnerGroupId { get; internal set; }
    }
}
