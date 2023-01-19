using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Messaging;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class ActivityLoaderTests
    {
        private class TestDataHandler : DataHandler
        {
            public int CallCount;
            public List<string> Calls = new();

            private int _lastId;
            public TestDataHandler(int lastId) : base(null, null)
            {
                _lastId = lastId;
            }

            internal override Task<IEnumerable<SecurityActivity>> LoadSecurityActivitiesAsync(int from, int to, int count, bool executingUnprocessedActivities,
                CancellationToken cancel)
            {
                CallCount++;
                Calls.Add($"LoadSecurityActivitiesAsync({from}, {to}, {count}, {executingUnprocessedActivities}, cancel)");

                var result = new List<SecurityActivity>();
                for (int i = from; i < Math.Min(from + count, _lastId + 1); i++)
                    result.Add(new ModifySecurityEntityOwnerActivity(1, 1) {Id = i});
                return Task.FromResult((IEnumerable<SecurityActivity>)result);
            }
            internal override Task<IEnumerable<SecurityActivity>> LoadSecurityActivitiesAsync(int[] gaps, bool executingUnprocessedActivities,
                CancellationToken cancel)
            {
                CallCount++;
                Calls.Add($"LoadSecurityActivitiesAsync([{string.Join(",", gaps.Select(x => x.ToString()))}], " +
                          $"{executingUnprocessedActivities}, cancel)");

                var result = gaps
                    .Select(i => new ModifySecurityEntityOwnerActivity(1, 1) {Id = i})
                    .ToArray();
                return Task.FromResult((IEnumerable<SecurityActivity>)result);
            }
        }

        [TestMethod]
        public void ActivityLoader_Section_HalfPage()
        {
            var lastId = 6;
            var expected = string.Join(",", Enumerable.Range(1, 6).Select(x => x.ToString()));
            var dataHandler = new TestDataHandler(lastId);

            // ACTION
            var loader = new SecurityActivityLoader(1, 10, true, dataHandler, 10);
            var actual = string.Join(",", loader.Select(x => x.Id.ToString()));

            // ASSERT
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(2, dataHandler.CallCount);
            Assert.AreEqual("LoadSecurityActivitiesAsync(1, 10, 10, True, cancel)", dataHandler.Calls[0]);
            Assert.AreEqual("LoadSecurityActivitiesAsync(7, 10, 10, True, cancel)", dataHandler.Calls[1]);
        }
        [TestMethod]
        public void ActivityLoader_Section_ExactlyOnePage()
        {
            var lastId = 10;
            var expected = string.Join(",", Enumerable.Range(1, 10).Select(x => x.ToString()));
            var dataHandler = new TestDataHandler(lastId);

            // ACTION
            var loader = new SecurityActivityLoader(1, 20, true, dataHandler, 10);
            var actual = string.Join(",", loader.Select(x => x.Id.ToString()));

            // ASSERT
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(2, dataHandler.CallCount);
            Assert.AreEqual("LoadSecurityActivitiesAsync(1, 20, 10, True, cancel)", dataHandler.Calls[0]);
            Assert.AreEqual("LoadSecurityActivitiesAsync(11, 20, 10, True, cancel)", dataHandler.Calls[1]);
        }
        [TestMethod]
        public void ActivityLoader_Section_TwoAndAHalfPage()
        {
            var lastId = 25;
            var expected = string.Join(",", Enumerable.Range(1, 25).Select(x => x.ToString()));
            var dataHandler = new TestDataHandler(lastId);

            // ACTION
            var loader = new SecurityActivityLoader(1, 30, true, dataHandler, 10);
            var actual = string.Join(",", loader.Select(x => x.Id.ToString()));

            // ASSERT
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(4, dataHandler.CallCount);
            Assert.AreEqual("LoadSecurityActivitiesAsync(1, 30, 10, True, cancel)", dataHandler.Calls[0]);
            Assert.AreEqual("LoadSecurityActivitiesAsync(11, 30, 10, True, cancel)", dataHandler.Calls[1]);
            Assert.AreEqual("LoadSecurityActivitiesAsync(21, 30, 10, True, cancel)", dataHandler.Calls[2]);
            Assert.AreEqual("LoadSecurityActivitiesAsync(26, 30, 10, True, cancel)", dataHandler.Calls[3]);
        }
        [TestMethod]
        public void ActivityLoader_Gap_HalfPage()
        {
            var lastId = 100;
            var ids = Enumerable.Range(1, 6).ToArray();
            var expected = string.Join(",", ids.Select(x => x.ToString()));
            var dataHandler = new TestDataHandler(lastId);

            // ACTION
            var loader = new SecurityActivityLoader(ids, true, dataHandler, 10);
            var actual = string.Join(",", loader.Select(x => x.Id.ToString()));

            // ASSERT
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(1, dataHandler.CallCount);
            Assert.AreEqual("LoadSecurityActivitiesAsync([1,2,3,4,5,6], True, cancel)", dataHandler.Calls[0]);
        }
        [TestMethod]
        public void ActivityLoader_Gap_ExactlyOnePage()
        {
            var lastId = 100;
            var ids = Enumerable.Range(1, 10).ToArray();
            var expected = string.Join(",", ids.Select(x => x.ToString()));
            var dataHandler = new TestDataHandler(lastId);

            // ACTION
            var loader = new SecurityActivityLoader(ids, true, dataHandler, 10);
            var actual = string.Join(",", loader.Select(x => x.Id.ToString()));

            // ASSERT
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(1, dataHandler.CallCount);
            Assert.AreEqual("LoadSecurityActivitiesAsync([1,2,3,4,5,6,7,8,9,10], True, cancel)", dataHandler.Calls[0]);
        }
        [TestMethod]
        public void ActivityLoader_Gap_TwoAndAHalfPage()
        {
            var lastId = 100;
            var ids = Enumerable.Range(1, 25).ToArray();
            var expected = string.Join(",", ids.Select(x => x.ToString()));
            var dataHandler = new TestDataHandler(lastId);

            // ACTION
            var loader = new SecurityActivityLoader(ids, true, dataHandler, 10);
            var actual = string.Join(",", loader.Select(x => x.Id.ToString()));

            // ASSERT
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(3, dataHandler.CallCount);
            Assert.AreEqual("LoadSecurityActivitiesAsync([1,2,3,4,5,6,7,8,9,10], True, cancel)", dataHandler.Calls[0]);
            Assert.AreEqual("LoadSecurityActivitiesAsync([11,12,13,14,15,16,17,18,19,20], True, cancel)", dataHandler.Calls[0]);
            Assert.AreEqual("LoadSecurityActivitiesAsync([21,22,23,24,25], True, cancel)", dataHandler.Calls[0]);
        }
    }
}
