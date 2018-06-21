using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Data;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class InMemTests : TestCases
    {
        protected override ISecurityDataProvider GetDataProvider()
        {
            MemoryDataProvider.LastActivityId = 0;
            return new MemoryDataProvider(DatabaseStorage.CreateEmpty());
        }
    }
}
