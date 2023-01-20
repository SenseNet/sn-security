using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using SenseNet.Diagnostics;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Messaging;

internal class SecurityActivityAsyncLoader
{
    private const int SecurityActivityLoadingBufferSize = 200;

    private readonly DataHandler _dataHandler;

    public SecurityActivityAsyncLoader(DataHandler dataHandler)
    {
        _dataHandler = dataHandler;
    }


    public async IAsyncEnumerable<SecurityActivity> LoadAsync(int from, int to, bool unprocessed, 
        [EnumeratorCancellation] CancellationToken cancel, int? pageSize = null)
    {
        var count = pageSize ?? SecurityActivityLoadingBufferSize;

        SecurityActivity[] buffer;
        while ((buffer = await LoadSegmentAsync(from, to, count, unprocessed, cancel).ConfigureAwait(false)).Length > 0)
        {
            foreach (var item in buffer)
                yield return item;

            if (buffer.Length < count)
                break;
            from += count;
        }
    }
    private async Task<SecurityActivity[]> LoadSegmentAsync(int from, int to, int count, bool unprocessed, CancellationToken cancel)
    {
        using var op = SnTrace.SecurityQueue.StartOperation(() => 
            $"SAQ: Loading segment: from: {from}, to: {to}, count: {count}.");
        var loaded = await _dataHandler.LoadSecurityActivitiesAsync(from, to, count, unprocessed, cancel)
            .ConfigureAwait(false);
        op.Successful = true;
        return loaded.ToArray();
    }

    public async IAsyncEnumerable<SecurityActivity> LoadAsync(int[] gaps, bool unprocessed,
        [EnumeratorCancellation] CancellationToken cancel, int? pageSize = null)
    {
        var count = pageSize ?? SecurityActivityLoadingBufferSize;

        SecurityActivity[] buffer;
        var gapIndex = 0;
        while ((buffer = await LoadGapsPageAsync(gaps.Skip(gapIndex).Take(count).ToArray(), unprocessed, cancel).ConfigureAwait(false)).Length > 0)
        {
            foreach (var item in buffer)
                yield return item;

            if (gapIndex + count >= gaps.Length)
                break;
            gapIndex += count;
        }
    }
    private async Task<SecurityActivity[]> LoadGapsPageAsync(int[] gaps, bool unprocessed, CancellationToken cancel)
    {
        using var op = SnTrace.SecurityQueue.StartOperation(() =>
            $"SAQ: Loading gaps (count: {gaps.Length}): [{string.Join(", ", gaps)}]");
        var loaded = await _dataHandler.LoadSecurityActivitiesAsync(gaps, unprocessed, cancel)
            .ConfigureAwait(false);
        op.Successful = true;
        return loaded.ToArray();
    }
}