using SenseNet.Diagnostics;
using SenseNet.Security.Messaging.SecurityMessages;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SenseNet.Security.Messaging
{
    internal class SecurityActivityLoader : IEnumerable<SecurityActivity>
    {
        private readonly bool gapLoader;

        private readonly int from;
        private readonly int to;
        private readonly int pageSize;
        private readonly int[] gaps;
        private readonly bool executingUnprocessedActivities;

        public SecurityActivityLoader(int from, int to, bool executingUnprocessedActivities)
        {
            gapLoader = false;
            this.from = from;
            this.to = to;
            this.executingUnprocessedActivities = executingUnprocessedActivities;
            this.pageSize = SecurityActivityQueue.SecurityActivityLoadingBufferSize;
        }
        //UNDONE: use the executingUnprocessedActivities if needed or remove
        // ReSharper disable once UnusedParameter.Local
        public SecurityActivityLoader(int[] gaps, bool executingUnprocessedActivities)
        {
            this.gapLoader = true;
            this.gaps = gaps;
            this.pageSize = SecurityActivityQueue.SecurityActivityLoadingBufferSize;
        }

        public IEnumerator<SecurityActivity> GetEnumerator()
        {
            if (gapLoader)
                return new GapLoader(this.gaps, this.pageSize, this.executingUnprocessedActivities);
            return new SectionLoader(this.from, this.to, this.pageSize, this.executingUnprocessedActivities);
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

            public SectionLoader(int from, int to, int pageSize, bool executingUnprocessedActivities)
            {
                this._from = from;
                this._to = to;
                this._pageSize = pageSize;
                this._executingUnprocessedActivities = executingUnprocessedActivities;

                this._buffer = new SecurityActivity[pageSize];
                this._loadedPageSize = this._buffer.Length;
                this._pointer = this._buffer.Length - 1;
            }

            public SecurityActivity Current => this._buffer[this._pointer];

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
                if (++this._pointer >= this._loadedPageSize)
                {
                    if (this._isLastPage)
                        return false;

                    LoadNextPage(this._buffer, out this._isLastPage, out this._loadedPageSize);
                    if (this._isLastPage && this._loadedPageSize == 0)
                        return false;

                    this._pointer = 0;
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
                    var segment = DataHandler.LoadSecurityActivities(from, to, count, _executingUnprocessedActivities);
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

            public GapLoader(int[] gaps, int pageSize, bool executingUnprocessedActivities)
            {
                _gaps = gaps;
                _pageSize = pageSize;
                _bufferIndex = pageSize;
                _executingUnprocessedActivities = executingUnprocessedActivities;
            }

            public SecurityActivity Current => this._buffer[this._bufferIndex];

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
                this._bufferIndex++;
                if (this._bufferIndex >= this._buffer.Count)
                {
                    LoadNextBuffer();
                    if (this._buffer.Count == 0 && this._gapIndex >= this._gaps.Length)
                        return false;
                    this._bufferIndex = 0;
                }
                return true;
            }
            private void LoadNextBuffer()
            {
                this._buffer.Clear();
                while (true)
                {
                    if (this._gapIndex >= this._gaps.Length)
                        break;
                    var gapPage = this._gaps.Skip(_gapIndex).Take(_pageSize).ToArray();
                    this._buffer.AddRange(LoadGaps(gapPage));
                    this._gapIndex += _pageSize;
                    if (this._buffer.Count >= this._pageSize)
                        break;
                }
            }
            private IEnumerable<SecurityActivity> LoadGaps(int[] gaps)
            {
                SnTrace.SecurityQueue.Write("SAQ: Loading gaps (count: {0}): [{1}]", gaps.Length, string.Join(", ", gaps));
                return DataHandler.LoadSecurityActivities(gaps, _executingUnprocessedActivities);
            }

        }
    }
}
