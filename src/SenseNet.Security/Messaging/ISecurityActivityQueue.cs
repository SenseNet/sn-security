using System;
using System.Threading.Tasks;
using System.Threading;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Messaging;

internal interface ISecurityActivityQueue
{
    SecurityActivityQueueState GetCurrentState();
    void Startup(CompletionState uncompleted, int lastActivityIdFromDb);
    Task StartAsync(CompletionState uncompleted, int lastActivityIdFromDb, CancellationToken cancel);
    void Shutdown();
    [Obsolete("SAQ: Use ExecuteActivityAsync instead.", false)]
    void ExecuteActivity(SecurityActivity activity);
    Task ExecuteActivityAsync(SecurityActivity activity, CancellationToken cancel);
    CompletionState GetCurrentCompletionState();
    void HealthCheck();
}