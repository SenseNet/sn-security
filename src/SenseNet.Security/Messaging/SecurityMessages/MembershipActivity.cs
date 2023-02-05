using System;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// Base class of membership related activities.
    /// </summary>
    [Serializable]
    public abstract class MembershipActivity : SecurityActivity
    {
        internal override bool ShouldWaitFor(SecurityActivity olderActivity)
        {
            return true;
        }
    }
}
