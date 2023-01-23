using SenseNet.Diagnostics;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Messaging
{
    internal class SecurityActivityQueue : ISecurityActivityQueue, IDisposable
    {
        private readonly DataHandler _dataHandler;
        private readonly CancellationTokenSource _mainCancellationSource;
        private readonly CancellationToken _mainCancellationToken;
        private Task _mainThreadControllerTask;

        public SecurityActivityQueue(DataHandler dataHandler)
        {
            _dataHandler = dataHandler;

            // initialize non-nullable fields
            _mainCancellationSource = new CancellationTokenSource();
            _mainCancellationToken = _mainCancellationSource.Token;
            _completionState = new CompletionState();
        }

        public void Shutdown()
        {
            Dispose();
        }
        public void Dispose()
        {
            _mainCancellationSource.Cancel();
            _waitToWorkSignal.Set();
            Task.Delay(100).GetAwaiter().GetResult();
            _mainThreadControllerTask.Dispose();
            _mainCancellationSource.Dispose();

            //UNDONE:SAQ: remove comment if the cleaning CompletionState is required when disposing the ActivityQueue
            //_lastExecutedId = 0;
            //_gaps.Clear();
            //_completionState = new CompletionState();

            SnTrace.SecurityQueue.Write("SAQ: disposed");
        }

        public void Startup(CompletionState uncompleted, int lastActivityIdFromDb)
        {
            StartAsync(uncompleted, lastActivityIdFromDb, CancellationToken.None).GetAwaiter().GetResult();
        }
        public async Task StartAsync(CompletionState uncompleted, int lastDatabaseId, CancellationToken cancel)
        {
            _lastExecutedId = uncompleted?.LastActivityId ?? 0;
            _gaps.Clear();
            if (uncompleted?.Gaps != null)
                _gaps.AddRange(uncompleted.Gaps);
            _completionState = new CompletionState { LastActivityId = _lastExecutedId, Gaps = _gaps.ToArray() };

            // Start worker thread
            if(_mainThreadControllerTask == null)
                _mainThreadControllerTask = Task.Factory.StartNew(
                    () => ControlActivityQueueThread(_mainCancellationToken),
                    _mainCancellationToken, TaskCreationOptions.LongRunning, TaskScheduler.Default);

            await Task.Delay(1, cancel);

            //UNDONE:SAQ: wait for finishing all unprocessed activities or not?
            await ExecuteUnprocessedActivitiesAtStartAsync(_lastExecutedId, _gaps, lastDatabaseId, cancel);
        }


        // ReSharper disable once UnusedParameter.Local
        private async Task ExecuteUnprocessedActivitiesAtStartAsync(int lastExecutedId, List<int> gaps, int lastDatabaseId, CancellationToken cancel)
        {
            SnTrace.SecurityQueue.Write($"Discovering unprocessed security activities");

            var count = 0;
            void Arrive(SecurityActivity activity)
            {
                SnTrace.SecurityQueue.Write("SAQ: Startup: activity arrived from db: SA{0}.", activity.Id);
                _arrivalQueue.Enqueue(activity);
                _waitToWorkSignal.Set();
                count++;
            }

            if (gaps.Any() || lastExecutedId < lastDatabaseId)
            {
                var loader = new SecurityActivityAsyncLoader(_dataHandler);
                if (gaps.Any())
                    await foreach (var loadedActivity in loader.LoadAsync(gaps.ToArray(), true, cancel).ConfigureAwait(false))
                        Arrive(loadedActivity);
                if (lastExecutedId < lastDatabaseId)
                    await foreach (var loadedActivity in loader.LoadAsync(lastExecutedId + 1, lastDatabaseId, true, cancel).ConfigureAwait(false))
                        Arrive(loadedActivity);
            }

            //SnLog.WriteInformation(string.Format(EventMessage.Information.ExecutingUnprocessedActivitiesFinished, count),
            SnTrace.SecurityQueue.Write($"Executing unprocessed security activities ({count}).");
        }

        // Activity arrival
        public void ExecuteActivity(SecurityActivity activity)
        {
            ExecuteActivityAsync(activity, CancellationToken.None);
        }
        public Task ExecuteActivityAsync(SecurityActivity activity, CancellationToken cancel)
        {
            if (!activity.FromDatabase && !activity.FromReceiver)
            {
                using var op = SnTrace.SecurityQueue.StartOperation(() => $"DataHandler: SaveActivity #SA{activity.Key}");
                _dataHandler.SaveActivityAsync(activity, cancel).GetAwaiter().GetResult();
                op.Successful = true;
            }

            if (activity.FromDatabase)
                SnTrace.SecurityQueue.Write(() => $"SAQ: Arrive from database #SA{activity.Key}");
            else if (activity.FromReceiver)
                SnTrace.SecurityQueue.Write(() => $"SAQ: Arrive from receiver #SA{activity.Key}");
            else
                SnTrace.SecurityQueue.Write(() => $"SAQ: Arrive #SA{activity.Key}");

            activity.CancellationToken = CancellationTokenSource.CreateLinkedTokenSource(cancel, _mainCancellationToken).Token;

            _arrivalQueue.Enqueue(activity);
            _waitToWorkSignal.Set(); //UNDONE:SAQ: This instruction should replaced to other places (timer?).

            return activity.CreateTaskForWait();
        }

        private readonly AutoResetEvent _waitToWorkSignal = new AutoResetEvent(false);
        private readonly ConcurrentQueue<SecurityActivity> _arrivalQueue = new();
        private readonly List<SecurityActivity> _waitingList = new();
        private readonly List<SecurityActivity> _executingList = new();
        private Task? _activityLoaderTask;
        private long _workCycle;

        private int _lastExecutedId;
        private readonly List<int> _gaps = new();
        private CompletionState _completionState;

        public CompletionState GetCurrentCompletionState()
        {
            return _completionState;
        }

        private void ControlActivityQueueThread(CancellationToken cancel)
        {
            SnTrace.SecurityQueue.Write("SAQT: started");
            var finishedList = new List<SecurityActivity>(); // temporary
            var lastStartedId = _lastExecutedId;

            while (true)
            {
                try
                {
                    if (cancel.IsCancellationRequested)
                        break;

                    // Wait if there is nothing to do
                    if (_waitingList.Count == 0 && _executingList.Count == 0)
                    {
                        var id = lastStartedId;
                        SnTrace.SecurityQueue.Write(() => $"SAQT: waiting for arrival #SA{id + 1}");
                        _waitToWorkSignal.WaitOne();
                    }

                    if (cancel.IsCancellationRequested)
                        break;

                    // Continue working
                    _workCycle++;
                    SnTrace.SecurityQueue.Write(() => $"SAQT: works (cycle: {_workCycle}, " +
                                                      $"_arrivalQueue.Count: {_arrivalQueue.Count}), " +
                                                      $"_executingList.Count: {_executingList.Count}");

                    LineUpArrivedActivities(_arrivalQueue, _waitingList);

                    // Iterate while the waiting list is not empty or should wait for arrival the next activity.
                    // Too early-arrived activities remain in the list (activity.Id > lastStartedId + 1)
                    // If the current activity is "unprocessed" (startup mode), it needs to process instantly and
                    //   skip not-loaded activities because the activity may process a gap.
                    while (_waitingList.Count > 0)
                    {
                        var activityToExecute = _waitingList[0];
                        if (activityToExecute is PlaceholderActivity placeholder)
                        {
                            _waitingList.RemoveAt(0);
                            lastStartedId = placeholder.LastId;
                            SnTrace.SecurityQueue.Write(() => $"SAQT: process placeholder #SA{activityToExecute.Key}. " +
                                                              $"LastId: {placeholder.LastId}");
                        }
                        else if (!activityToExecute.IsUnprocessedActivity && activityToExecute.Id <= lastStartedId) // already arrived or executed
                        {
                            _waitingList.RemoveAt(0);
                            AttachOrIgnore(activityToExecute, _executingList);
                        }
                        else if (activityToExecute.IsUnprocessedActivity || activityToExecute.Id == lastStartedId + 1) // arrived in order
                        {
                            _waitingList.RemoveAt(0);
                            lastStartedId = ExecuteOrChain(activityToExecute, _executingList);
                        }
                        else
                        {
                            // Load the missed out activities from database or skip this if it is happening right now.
                            var id = lastStartedId;
                            _activityLoaderTask ??= Task.Run(() => LoadLastActivities(id + 1, cancel));
                            break; //UNDONE:SAQ: are you sure to exit here?
                        }
                    }

                    // Enumerate parallel-executable activities. Dependencies are attached or chained.
                    // (activity.WaitingFor.Count == 0)
                    SuperviseExecutions(_executingList, finishedList, cancel); // manage pending, execution and finished states

                    // Releases starter threads with attachments and activates dependent items
                    ManageFinishedActivities(finishedList, _executingList);

                    // End of cycle
                    SnTrace.SecurityQueue.Write(() => $"SAQT: wait a bit.");
                    Task.Delay(1).Wait();
                }
                catch (Exception e)
                {
                    SnTrace.SecurityQueue.WriteError(() => e.ToString());

                    //UNDONE:SAQ: Cancel all waiting tasks
                    _waitingList.FirstOrDefault()?.StartFinalizationTask();

                    break;
                }
            }

            SnTrace.SecurityQueue.Write("SAQT: finished");
        }
        private void LineUpArrivedActivities(ConcurrentQueue<SecurityActivity> arrivalQueue, List<SecurityActivity> waitingList)
        {
            // Move arrived items to the waiting list
            while (arrivalQueue.Count > 0)
            {
                if (arrivalQueue.TryDequeue(out var arrivedActivity))
                    waitingList.Add(arrivedActivity);
            }

            waitingList.Sort((x, y) => x.Id.CompareTo(y.Id));
            SnTrace.SecurityQueue.Write(() => $"SAQT: arrivalSortedList.Count: {waitingList.Count}");
        }
        private void AttachOrIgnore(SecurityActivity activity, List<SecurityActivity> executingList)
        {
            var existing = GetAllFromChains(executingList)
                .FirstOrDefault(x => x.Id == activity.Id);
            if (existing != null)
            {
                SnTrace.SecurityQueue.Write(() => $"SAQT: activity attached to another one: " +
                                                  $"#SA{activity.Key} -> SA{existing.Key}");
                existing.Attach(activity);
            }
            else
            {
                SnTrace.SecurityQueue.Write(() =>
                    $"SAQT: execution ignored immediately: #SA{activity.Key}");
                activity.StartFinalizationTask();
            }
        }
        private int ExecuteOrChain(SecurityActivity activity, List<SecurityActivity> executingList)
        {
            // Discover dependencies
            foreach (var activityUnderExecution in GetAllFromChains(executingList))
                if (activity.ShouldWaitFor(activityUnderExecution))
                    activity.WaitFor(activityUnderExecution);

            // Add to concurrently executable list
            if (activity.WaitingFor.Count == 0)
            {
                SnTrace.SecurityQueue.Write(() => $"SAQT: moved to executing list: #SA{activity.Key}");
                executingList.Add(activity);
            }

            // Mark as started even if it is waiting.
            return activity.Id;
        }
        private async Task LoadLastActivities(int fromId, CancellationToken cancel)
        {
            ConfiguredCancelableAsyncEnumerable<SecurityActivity> loaded;
            using (var op = SnTrace.SecurityQueue.StartOperation(() => $"DataHandler: LoadLastActivities(fromId: {fromId})"))
            {
                var loader = new SecurityActivityAsyncLoader(_dataHandler);
                loaded = loader.LoadAsync(fromId, int.MaxValue, false, cancel).ConfigureAwait(false);
                op.Successful = true;
            }

            int expectedId = fromId;
            await foreach (var activity in loaded)
            {
                if (activity.Id != expectedId)
                {
                    var firstId = expectedId;
                    var lastId = activity.Id - 1;
                    if (activity.Id > expectedId + 1)
                        SnTrace.SecurityQueue.Write(() => $"SAQ: missing from database #SA{firstId}..#SA{lastId}");
                    else
                        SnTrace.SecurityQueue.Write(() => $"SAQ: missing from database #SA{firstId}");

                    _arrivalQueue.Enqueue(new PlaceholderActivity(firstId, lastId));
                    expectedId = activity.Id;
                }
                SnTrace.SecurityQueue.Write(() => $"SAQ: Arrive from database #SA{activity.Key}");
                _arrivalQueue.Enqueue(activity);
                _waitToWorkSignal.Set();
                expectedId++;
            }
            // Unlock loading
            _activityLoaderTask = null;
        }
        private readonly TaskStatus?[] _finishedTaskStates = { TaskStatus.RanToCompletion, TaskStatus.Canceled, TaskStatus.Faulted };
        private void SuperviseExecutions(List<SecurityActivity> executingList, List<SecurityActivity> finishedList, CancellationToken cancel)
        {
            // Considered states:
            // - not created: null
            // - pending: Created, WaitingForActivation, WaitingToRun
            // - finished: RanToCompletion, Canceled, Faulted
            // - executing: Running, WaitingForChildrenToComplete
            var toStart = executingList
                .Where(x => x.GetExecutionTaskStatus() == null)
                .ToArray();
            var toRelease = executingList
                .Where(x => _finishedTaskStates.Contains(x.GetExecutionTaskStatus()))
                .ToArray();

            foreach (var activityToStart in toStart)
            {
                SnTrace.SecurityQueue.Write(() => $"SAQT: start execution: #SA{activityToStart.Key}");
                // Start the activity's execution task in an async way to ensure separate tasks for each one
                // otherwise, separation would only occur at first awaited instructions of each implementation.
                Task.Run(() => activityToStart.StartExecutionTask(), cancel);
            }

            foreach (var finishedActivity in toRelease)
            {
                finishedList.Add(finishedActivity);
            }
        }
        private void ManageFinishedActivities(List<SecurityActivity> finishedList, List<SecurityActivity> executingList)
        {
            foreach (var finishedActivity in finishedList)
            {
                SnTrace.SecurityQueue.Write(() => $"SAQT: execution finished: #SA{finishedActivity.Key}");
                //UNDONE:SAQ: memorize activity in the ActivityHistory?
                finishedActivity.StartFinalizationTask();
                executingList.Remove(finishedActivity);
                FinishActivity(finishedActivity);

                foreach (var attachment in finishedActivity.GetAttachments())
                {
                    SnTrace.SecurityQueue.Write(() => $"SAQT: execution ignored (attachment): #SA{attachment.Key}");
                    attachment.StartFinalizationTask();
                }

                finishedActivity.ClearAttachments();

                // Handle dependencies: start completely freed dependent activities by adding them to executing-list.
                foreach (var dependentActivity in finishedActivity.WaitingForMe.ToArray())
                {
                    SnTrace.SecurityQueue.Write(() => $"SAQT: activate dependent: #SA{dependentActivity.Key}");
                    dependentActivity.FinishWaiting(finishedActivity);
                    if (dependentActivity.WaitingFor.Count == 0)
                        executingList.Add(dependentActivity);
                }
            }

            finishedList.Clear();
        }
        private void FinishActivity(SecurityActivity activity)
        {
            var id = activity.Id;
            if (activity.ExecutionException == null)
            {
                if (id > _lastExecutedId)
                {
                    if (id > _lastExecutedId + 1)
                        _gaps.AddRange(Enumerable.Range(_lastExecutedId + 1, id - _lastExecutedId - 1));
                    _lastExecutedId = id;
                }
                else
                {
                    _gaps.Remove(id);
                }
                _completionState = new CompletionState { LastActivityId = _lastExecutedId, Gaps = _gaps.ToArray() };
                SnTrace.SecurityQueue.Write(() => $"SAQT: State after finishing SA{id}: {_completionState}");
            }
        }
        private IEnumerable<SecurityActivity> GetAllFromChains(List<SecurityActivity> roots)
        {
            var flattened = new List<SecurityActivity>(roots);
            var index = 0;
            while (index < flattened.Count)
            {
                yield return flattened[index];
                flattened.AddRange(flattened[index].WaitingForMe);
                index++;
            }
        }

        /* ======================================================================================== */

        public SecurityActivityQueueState GetCurrentState()
        {
            throw new NotImplementedException();
        }
        public void HealthCheck()
        {
            throw new NotImplementedException();
        }

    }
}
