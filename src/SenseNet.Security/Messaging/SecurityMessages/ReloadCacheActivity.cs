﻿using System;
using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages;

/// <summary>
/// Represents an activity that reloads the security cache as soon as all other active activities are finished.
/// </summary>
[Serializable]
public class ReloadCacheActivity : SecurityActivity
{
    public bool RemoteOnly { get; set; }

    public ReloadCacheActivity() { }

    public ReloadCacheActivity(bool remoteOnly)
    {
        RemoteOnly = remoteOnly;
    }

    protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
    {
        // do nothing
        return Task.CompletedTask;
    }

    protected override void Apply(SecurityContext context)
    {
        if (RemoteOnly && context.SecuritySystem.MessageSenderManager.IsMe(this.Sender))
            return;
        context.SecuritySystem.Cache.Reset();
    }

    internal override bool ShouldWaitFor(SecurityActivity olderActivity)
    {
        return true;
    }
}
