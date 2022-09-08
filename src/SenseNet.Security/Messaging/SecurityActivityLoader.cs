using SenseNet.Diagnostics;
using SenseNet.Security.Messaging.SecurityMessages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace SenseNet.Security.Messaging
{
    internal class SecurityActivityLoader : IEnumerable<SecurityActivity>
    {
        private readonly bool _gapLoader;

        private readonly int _from;
        private readonly int _to;
        private readonly int _pageSize;
        private readonly int[] _gaps;
        private readonly bool _executingUnprocessedActivities;
        private readonly DataHandler _dataHandler;

        public SecurityActivityLoader(int from, int to, bool executingUnprocessedActivities, DataHandler dataHandler)
        {
            _gapLoader = false;
            _from = from;
            _to = to;
            _executingUnprocessedActivities = executingUnprocessedActivities;
            _dataHandler = dataHandler;
            _pageSize = SecurityActivityQueue.SecurityActivityLoadingBufferSize;
        }
        // ReSharper disable once UnusedParameter.Local
        public SecurityActivityLoader(int[] gaps, bool executingUnprocessedActivities, DataHandler dataHandler)
        {
            _gapLoader = true;
            _gaps = gaps;
            _dataHandler = dataHandler;
            _pageSize = SecurityActivityQueue.SecurityActivityLoadingBufferSize;
        }

        public IEnumerator<SecurityActivity> GetEnumerator()
        {
            if (_gapLoader)
                return new GapLoader(_gaps, _pageSize, _executingUnprocessedActivities, _dataHandler);
            return new SectionLoader(_from, _to, _pageSize, _executingUnprocessedActivities, _dataHandler);
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        private class SectionLoader : IEnumerator<SecurityActivity>
        {
            private int _from;
            private readonly int _to;
            private readonly int _pageSize;

            private readonly SecurityActivity[] _buffer;
            private int _pointer;
            private bool _isLastPage;
            private int _loadedPageSize;
            private readonly bool _executingUnprocessedActivities;
            private readonly DataHandler _dataHandler;

            public SectionLoader(int from, int to, int pageSize, bool executingUnprocessedActivities, DataHandler dataHandler)
            {
                _from = from;
                _to = to;
                _pageSize = pageSize;
                _executingUnprocessedActivities = executingUnprocessedActivities;
                _dataHandler = dataHandler;

                _buffer = new SecurityActivity[pageSize];
                _loadedPageSize = _buffer.Length;
                _pointer = _buffer.Length - 1;
            }

            public SecurityActivity Current => _buffer[_pointer];

            object System.Collections.IEnumerator.Current => Current;

            public void Reset()
            {
                throw new NotSupportedException();
            }
            public void Dispose()
            {
                // does nothing
            }

            public bool MoveNext()
            {
                if (++_pointer >= _loadedPageSize)
                {
                    if (_isLastPage)
                        return false;

                    LoadNextPage(_buffer, out _isLastPage, out _loadedPageSize);
                    if (_isLastPage && _loadedPageSize == 0)
                        return false;

                    _pointer = 0;
                }
                return true;
            }
            private void LoadNextPage(SecurityActivity[] buffer, out bool isLast, out int count)
            {
                count = 0;

                foreach (var item in LoadSegment(_from, _to, _pageSize))
                    buffer[count++] = item;

                if (count < 1)
                {
                    isLast = true;
                    return;
                }

                var last = buffer[count - 1];
                _from = last.Id + 1;

                isLast = last.Id >= _to;
            }
            private IEnumerable<SecurityActivity> LoadSegment(int from, int to, int count)
            {
                using (var op = SnTrace.SecurityQueue.StartOperation("SAQ: Loading segment: from: {0}, to: {1}, count: {2}.", from, to, count))
                {
                    var segment = _dataHandler.LoadSecurityActivitiesAsync(from, to, count,
                        _executingUnprocessedActivities, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
                    op.Successful = true;
                    return segment;
                }
            }
        }

        private class GapLoader : IEnumerator<SecurityActivity>
        {
            private readonly int[] _gaps;
            private int _gapIndex;
            private readonly List<SecurityActivity> _buffer = new List<SecurityActivity>();
            private int _bufferIndex;
            private readonly int _pageSize;
            private readonly bool _executingUnprocessedActivities;
            private readonly DataHandler _dataHandler;

            public GapLoader(int[] gaps, int pageSize, bool executingUnprocessedActivities, DataHandler dataHandler)
            {
                _gaps = gaps;
                _pageSize = pageSize;
                _bufferIndex = pageSize;
                _executingUnprocessedActivities = executingUnprocessedActivities;
                _dataHandler = dataHandler;
            }

            public SecurityActivity Current => _buffer[_bufferIndex];

            object System.Collections.IEnumerator.Current => Current;

            public void Reset()
            {
                throw new NotSupportedException();
            }
            public void Dispose()
            {
                // does nothing
            }

            public bool MoveNext()
            {
                _bufferIndex++;
                if (_bufferIndex >= _buffer.Count)
                {
                    LoadNextBuffer();
                    if (_buffer.Count == 0 && _gapIndex >= _gaps.Length)
                        return false;
                    _bufferIndex = 0;
                }
                return true;
            }
            private void LoadNextBuffer()
            {
                _buffer.Clear();
                while (true)
                {
                    if (_gapIndex >= _gaps.Length)
                        break;
                    var gapPage = _gaps.Skip(_gapIndex).Take(_pageSize).ToArray();
                    _buffer.AddRange(LoadGaps(gapPage));
                    _gapIndex += _pageSize;
                    if (_buffer.Count >= _pageSize)
                        break;
                }
            }
            private IEnumerable<SecurityActivity> LoadGaps(int[] gaps)
            {
                SnTrace.SecurityQueue.Write("SAQ: Loading gaps (count: {0}): [{1}]", gaps.Length, string.Join(", ", gaps));
                return _dataHandler.LoadSecurityActivitiesAsync(gaps, _executingUnprocessedActivities, CancellationToken.None)
                    .ConfigureAwait(false).GetAwaiter().GetResult();
            }

        }
    }
}
