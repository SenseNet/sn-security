using System;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages;

/// <summary>
/// Represents an activity that reloads the security cache after any other active security activity is finished activity.
/// </summary>
[Serializable]
public class ReloadCacheActivity : SecurityActivity
{
    public ReloadCacheActivity() { }

    protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
    {
        // do nothing
        return Task.CompletedTask;
    }

    protected override void Apply(SecurityContext context)
    {
        context.SecuritySystem.Cache.Reset();
    }

    internal override bool ShouldWaitFor(SecurityActivity olderActivity)
    {
        return true;
    }
}