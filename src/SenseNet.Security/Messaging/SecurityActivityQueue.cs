using SenseNet.Diagnostics;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Messaging
{
    internal class SecurityActivityQueue : IDisposable
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
            _mainThreadControllerTask = Task.CompletedTask;
            _completionState = new CompletionState();
        }

        public void Dispose()
        {
            _mainCancellationSource.Cancel();
            _waitToWorkSignal.Set();
            Task.Delay(100).GetAwaiter().GetResult();
            _mainThreadControllerTask.Dispose();
            _mainCancellationSource.Dispose();

            //UNDONE: SAQ: remove comment if the cleaning CompletionState is required when disposing the ActivityQueue
            //_lastExecutedId = 0;
            //_gaps.Clear();
            //_completionState = new CompletionState();

            SnTrace.Write("SAQ: disposed");
        }

        public async Task StartAsync(CancellationToken cancel)
        {
            var dbState = await _dataHandler.LoadCompletionStateAsync(cancel);
            await StartAsync(dbState.CompletionState, dbState.LastDatabaseId, cancel);
        }
        public async Task StartAsync(CompletionState uncompleted, int lastDatabaseId, CancellationToken cancel)
        {
            _lastExecutedId = uncompleted?.LastActivityId ?? 0;
            _gaps.Clear();
            if (uncompleted?.Gaps != null)
                _gaps.AddRange(uncompleted.Gaps);
            _completionState = new CompletionState { LastActivityId = _lastExecutedId, Gaps = _gaps.ToArray() };

            // Start worker thread
            _mainThreadControllerTask = Task.Factory.StartNew(
                () => ControlActivityQueueThread(_mainCancellationToken),
                _mainCancellationToken, TaskCreationOptions.LongRunning, TaskScheduler.Default);

            await Task.Delay(1, cancel);

            //UNDONE: SAQ: wait for finishing all unprocessed activities or not?
            await ExecuteUnprocessedActivitiesAtStartAsync(_lastExecutedId, _gaps, lastDatabaseId, cancel);
        }
        // ReSharper disable once UnusedParameter.Local
        private Task ExecuteUnprocessedActivitiesAtStartAsync(int lastExecutedId, List<int> gaps, int lastDatabaseId, CancellationToken cancel)
        {
            var count = 0;
            SnTrace.Write($"Discovering unprocessed security activities");
            if (gaps.Any())
            {
                var loadedActivities = new SecurityActivityLoader(gaps.ToArray(), true, _dataHandler);
                foreach (var loadedActivity in loadedActivities)
                {
                    SnTrace.SecurityQueue.Write("SAQ: Startup: activity arrived from db: SA{0}.", loadedActivity.Id);
                    _arrivalQueue.Enqueue(loadedActivity);
                    _waitToWorkSignal.Set();
                    count++;
                }
            }
            if (lastExecutedId < lastDatabaseId)
            {
                var loadedActivities = new SecurityActivityLoader(lastExecutedId + 1, lastDatabaseId, true, _dataHandler);
                foreach (var loadedActivity in loadedActivities)
                {
                    SnTrace.SecurityQueue.Write("SAQ: Startup: activity arrived from db: SA{0}.", loadedActivity.Id);
                    _arrivalQueue.Enqueue(loadedActivity);
                    _waitToWorkSignal.Set();
                    count++;
                }
            }
            //SnLog.WriteInformation(string.Format(EventMessage.Information.ExecutingUnprocessedActivitiesFinished, count),
            SnTrace.Write($"Executing unprocessed security activities ({count}).");

            return Task.CompletedTask;
        }

        // Activity arrival
        public Task ExecuteAsync(SecurityActivity activity, CancellationToken cancel)
        {
            if (!activity.FromDatabase && !activity.FromReceiver)
                _dataHandler.SaveActivityAsync(activity, cancel).GetAwaiter().GetResult();

            if (activity.FromReceiver)
                SnTrace.Write(() => $"SAQ: Arrive from receiver #SA{activity.Key}");
            else
                SnTrace.Write(() => $"SAQ: Arrive #SA{activity.Key}");

            activity.CancellationToken = CancellationTokenSource.CreateLinkedTokenSource(cancel, _mainCancellationToken).Token;

            _arrivalQueue.Enqueue(activity);
            _waitToWorkSignal.Set(); //UNDONE: SAQ: This instruction should replaced to other places (timer?).

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

        public CompletionState GetCompletionState()
        {
            return _completionState;
        }

        private void ControlActivityQueueThread(CancellationToken cancel)
        {
            SnTrace.Write("SAQT: started");
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
                        SnTrace.Write(() => $"SAQT: waiting for arrival #SA{id + 1}");
                        _waitToWorkSignal.WaitOne();
                    }

                    if (cancel.IsCancellationRequested)
                        break;

                    // Continue working
                    _workCycle++;
                    SnTrace.Write(() => $"SAQT: works (cycle: {_workCycle}, " +
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
                        if (!activityToExecute.IsUnprocessedActivity && activityToExecute.Id <= lastStartedId) // already arrived or executed
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
                            break; //UNDONE: SAQ: are you sure to exit here?
                        }
                    }

                    // Enumerate parallel-executable activities. Dependencies are attached or chained.
                    // (activity.WaitingFor.Count == 0)
                    SuperviseExecutions(_executingList, finishedList, cancel); // manage pending, execution and finished states

                    // Releases starter threads with attachments and activates dependent items
                    ManageFinishedActivities(finishedList, _executingList);

                    // End of cycle
                    SnTrace.Write(() => $"SAQT: wait a bit.");
                    Task.Delay(1).Wait();
                }
                catch (Exception e)
                {
                    SnTrace.WriteError(() => e.ToString());

                    //UNDONE: SAQ: Cancel all waiting tasks
                    _waitingList.FirstOrDefault()?.StartFinalizationTask();

                    break;
                }
            }

            SnTrace.Write("SAQT: finished");
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
            SnTrace.Write(() => $"SAQT: arrivalSortedList.Count: {waitingList.Count}");
        }
        private void AttachOrIgnore(SecurityActivity activity, List<SecurityActivity> executingList)
        {
            var existing = GetAllFromChains(executingList)
                .FirstOrDefault(x => x.Id == activity.Id);
            if (existing != null)
            {
                SnTrace.Write(() => $"SAQT: activity attached to another one: " +
                                    $"#SA{activity.Key} -> SA{existing.Key}");
                existing.Attachments.Add(activity);
            }
            else
            {
                SnTrace.Write(() =>
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
                SnTrace.Write(() => $"SAQT: moved to executing list: #SA{activity.Key}");
                executingList.Add(activity);
            }

            // Mark as started even if it is waiting.
            return activity.Id;
        }
        private async Task LoadLastActivities(int fromId, CancellationToken cancel)
        {
            var loaded = await _dataHandler.LoadLastActivities(fromId, cancel);
            foreach (var activity in loaded)
            {
                SnTrace.Write(() => $"SAQ: Arrive from database #SA{activity.Key}");
                _arrivalQueue.Enqueue(activity);
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
                SnTrace.Write(() => $"SAQT: start execution: #SA{activityToStart.Key}");
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
                SnTrace.Write(() => $"SAQT: execution finished: #SA{finishedActivity.Key}");
                //UNDONE: SAQ: memorize activity in the ActivityHistory?
                finishedActivity.StartFinalizationTask();
                executingList.Remove(finishedActivity);
                FinishActivity(finishedActivity);

                foreach (var attachment in finishedActivity.Attachments)
                {
                    SnTrace.Write(() => $"SAQT: execution ignored (attachment): #SA{attachment.Key}");
                    attachment.StartFinalizationTask();
                }

                finishedActivity.Attachments.Clear();

                // Handle dependencies: start completely freed dependent activities by adding them to executing-list.
                foreach (var dependentActivity in finishedActivity.WaitingForMe.ToArray())
                {
                    SnTrace.Write(() => $"SAQT: activate dependent: #SA{dependentActivity.Key}");
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
                SnTrace.Write(() => $"SAQT: State after finishing SA{id}: {_completionState}");
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
    }
}
