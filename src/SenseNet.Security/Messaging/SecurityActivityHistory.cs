using System;
using System.Collections.Generic;
using System.Linq;
using SenseNet.Security.Messaging.SecurityMessages;
using Newtonsoft.Json;
using SenseNet.Diagnostics;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Contains momentary state information about the security activity execution
    /// and the recent processed activities in details.
    /// </summary>
    public class SecurityActivityHistory
    {
        /// <summary>
        /// Contains momentary state information about the security activity execution.
        /// </summary>
        public SecurityActivityQueueState State { get; internal set; }

        /// <summary>
        /// It is empty or contains a message about any error in connection with the SecurityActivityHistory feature.
        /// </summary>
        public string Message { get; internal set; }


        /// <summary>
        /// Length of the Recent
        /// </summary>
        public int RecentLength => Recent?.Length ?? 0;

        /// <summary>
        /// Array of the recently executed activities.
        /// </summary>
        public SecurityActivityHistoryItem[] Recent { get; internal set; }

        internal string GetJson()
        {
            try
            {
                var writer = new System.IO.StringWriter();
                WriteJson(writer);
                return writer.GetStringBuilder().ToString();
            }
            catch
            {
                return "SERIALIZATION ERROR";
            }
        }
        internal void WriteJson(System.IO.TextWriter writer)
        {
            JsonSerializer.Create(new JsonSerializerSettings
            {
                //NullValueHandling = NullValueHandling.Ignore,
                Formatting = Formatting.Indented
            })
            .Serialize(writer, this);
        }
    }

    public class SecurityActivityHistoryController
    {
        internal SecurityActivityHistory GetHistory()
        {
            SecurityActivityHistory result;
            var list = new List<SecurityActivityHistoryItem>(_history.Length);
            lock (_lock)
            {
                for (var i = _position; i < _history.Length; i++)
                    if (_history[i] != null)
                        list.Add(_history[i]);
                for (var i = 0; i < _position; i++)
                    if (_history[i] != null)
                        list.Add(_history[i]);

                result = new SecurityActivityHistory
                {
                    State = SecuritySystem.Instance.SecurityActivityQueue.GetCurrentState(),
                    Recent = list.ToArray(),
                    Message = _unfinished < 1 ? null : "RECENT ARRAY TOO SHORT. Cannot register the full activity lifecycle. Unfinished items: " + _unfinished
                };
            }
            return result;
        }
        internal SecurityActivityHistory Reset()
        {
            SecurityActivityHistory result;
            lock (_lock)
            {
                for (var i = 0; i < _history.Length; i++)
                    _history[i] = null;

                _position = 0;
                _unfinished = 0;

                result = new SecurityActivityHistory
                {
                    State = SecuritySystem.Instance.SecurityActivityQueue.GetCurrentState(),
                    Recent = new SecurityActivityHistoryItem[0]
                };
            }
            return result;
        }

        internal void _traceHistoryCount(string msg)
        {
            var count = _history.Count(x => x != null);
            SnTrace.Write($">>>> history active items ({msg}): {count}");
        }

        private readonly object _lock = new object();
        private const int HistoryLength = 1023;
        private readonly SecurityActivityHistoryItem[] _history = new SecurityActivityHistoryItem[HistoryLength];
        private int _position;
        private int _unfinished;

        internal void Arrive(SecurityActivity activity)
        {
            lock (_lock)
            {
                // avoid duplication
                if (_history.Any(item => item != null && item.Id == activity.Id))
                    return;

                var retired = _history[_position];
                _history[_position] = new SecurityActivityHistoryItem
                {
                    Id = activity.Id,
                    TypeName = activity.TypeName,
                    FromReceiver = activity.FromReceiver,
                    FromDb = activity.FromDatabase,
                    IsStartup = activity.IsUnprocessedActivity,
                    ArrivedAt = DateTime.UtcNow,
                    StartedAt = DateTime.MinValue,
                    FinishedAt = DateTime.MinValue
                };

                if (retired != null)
                    if (retired.FinishedAt == DateTime.MinValue)
                        _unfinished++;

                _position++;
                if (_position >= HistoryLength)
                    _position = 0;
            }
        }
        internal void Wait(SecurityActivity activity)
        {
            lock (_lock)
            {
                foreach (var item in _history)
                {
                    if (item != null && item.Id == activity.Id)
                    {
                        item.WaitedFor = activity.WaitingFor.Select(a => a.Id).ToArray();
                        break;
                    }
                }
            }
        }
        internal void Start(int activityId)
        {
            lock (_lock)
            {
                foreach (var item in _history)
                {
                    if (item != null && item.Id == activityId)
                    {
                        item.StartedAt = DateTime.UtcNow;
                        return;
                    }
                }
                SnTrace.SecurityQueue.Write("SAQ: SA{0} DOES NOT FOUND IN HISTORY. Cannot register the 'start' event.", activityId);
            }
        }
        internal void Finish(int activityId)
        {
            lock (_lock)
            {
                foreach (var item in _history)
                {
                    if (item != null && item.Id == activityId)
                    {
                        item.FinishedAt = DateTime.UtcNow;
                        return;
                    }
                }
            }
            SnTrace.SecurityQueue.Write("SAQ: SA{0} DOES NOT FOUND IN HISTORY. Cannot register the 'stop' event.", activityId);
        }
        internal void Error(int activityId, Exception e)
        {
            lock (_lock)
            {
                foreach (var item in _history)
                {
                    if (item != null && item.Id == activityId)
                    {
                        item.Error = e.GetType().Name + ": " + e.Message;
                        return;
                    }
                }
            }
            SnTrace.SecurityQueue.Write("SAQ: SA{0} DOES NOT FOUND IN HISTORY. Cannot register an 'error' on it.", activityId);
        }
    }

    /// <summary>
    /// Contains information about the serialized activities on the arrival size.
    /// </summary>
    public class SecurityActivitySerializerState
    {
        /// <summary>
        /// Id of the last arrived activity.
        /// </summary>
        public int LastQueued { get; set; }
        /// <summary>
        /// Length of the Queue
        /// </summary>
        public int QueueLength => Queue?.Length ?? 0;

        /// <summary>
        /// Ids of th Arrived but not parallel activities.
        /// </summary>
        public int[] Queue { get; set; }
    }
    /// <summary>
    /// Contains information about the waiting activities.
    /// </summary>
    public class SecurityActivityDependencyState
    {
        /// <summary>
        /// Length of the WaitingSet.
        /// </summary>
        public int WaitingSetLength => WaitingSet?.Length ?? 0;

        /// <summary>
        /// Ids of the all waiting activities.
        /// </summary>
        public int[] WaitingSet { get; set; }
    }
    /// <summary>
    /// Contains information about the executed activities.
    /// </summary>
    public class CompletionState
    {
        /// <summary>
        /// Id of the last executed activity.
        /// </summary>
        public int LastActivityId { get; set; }
        /// <summary>
        /// Length of the Gaps array.
        /// </summary>
        public int GapsLength => Gaps?.Length ?? 0;

        /// <summary>
        /// Contains activity ids that are not executed yet and are lower than the LastActivityId.
        /// </summary>
        public int[] Gaps { get; set; }

        /// <summary>
        /// Initializes a new instance of the CompletionState class.
        /// </summary>
        public CompletionState()
        {
            Gaps = new int[0];
        }

        internal static CompletionState GetCurrent()
        {
            return SecuritySystem.Instance.SecurityActivityQueue.GetCurrentCompletionState();
        }

        /// <summary>
        /// Returns a string that represents the current object.
        /// </summary>
        public override string ToString()
        {
            return $"{LastActivityId}({GapsToString(Gaps, 50, 10)})";
        }

        internal static object GapsToString(int[] gaps, int maxCount, int growth)
        {
            if (gaps.Length < maxCount + growth)
                maxCount = gaps.Length;
            return gaps.Length > maxCount
                ? $"{string.Join(",", gaps.Take(maxCount))},... and {gaps.Length - maxCount} additional items"
                : string.Join(",", gaps);
        }
    }
    /// <summary>
    /// Contains momentary state information about the security activity execution for debugging purposes.
    /// </summary>
    public class SecurityActivityQueueState
    {
        /// <summary>
        /// Activity serializer state on the arrival side.
        /// </summary>
        public SecurityActivitySerializerState Serializer { get; set; }
        /// <summary>
        /// State of the waiting activities.
        /// </summary>
        public SecurityActivityDependencyState DependencyManager { get; set; }
        /// <summary>
        /// State of the executed activities.
        /// </summary>
        public CompletionState Termination { get; set; }
    }

    /// <summary>
    /// Contains debug information about a security activity execution.
    /// </summary>
    public class SecurityActivityHistoryItem
    {
        /// <summary>
        /// Id of the activity.
        /// </summary>
        public int Id { get; set; }
        /// <summary>
        /// Short name of the activity type.
        /// </summary>
        public string TypeName { get; set; }
        /// <summary>
        /// True if the activity was received from another computer.
        /// </summary>
        public bool FromReceiver { get; set; }
        /// <summary>
        /// True if the activity was loaded from the database.
        /// </summary>
        public bool FromDb { get; set; }
        /// <summary>
        /// True if the activity is instantiated during in the startup process.
        /// </summary>
        public bool IsStartup { get; set; }
        /// <summary>
        /// Contains error message if the activity execution was unsuccessful.
        /// </summary>
        public string Error { get; set; }
        /// <summary>
        /// Ids of the activities that are delayed the execution of this activity.
        /// </summary>
        public int[] WaitedFor { get; set; }
        /// <summary>
        /// Arrival time.
        /// </summary>
        public DateTime ArrivedAt { get; set; }
        /// <summary>
        /// Time of the execution start.
        /// </summary>
        public DateTime StartedAt { get; set; }
        /// <summary>
        /// Time of the execution end.
        /// </summary>
        public DateTime FinishedAt { get; set; }
        /// <summary>
        /// Waiting time (StartedAt - ArrivedAt)
        /// </summary>
        public TimeSpan WaitTime => StartedAt - ArrivedAt;

        /// <summary>
        /// Execution time (FinishedAt - StartedAt)
        /// </summary>
        public TimeSpan ExecTime => FinishedAt - StartedAt;

        /// <summary>
        /// Full time (FinishedAt - ArrivedAt)
        /// </summary>
        public TimeSpan FullTime => FinishedAt - ArrivedAt;
    }
}
