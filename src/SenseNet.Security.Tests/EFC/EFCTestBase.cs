using System.Configuration;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.EFCSecurityStore;
using SenseNet.Security.Tests.TestPortal;
// ReSharper disable UnusedVariable
// ReSharper disable InconsistentNaming

namespace SenseNet.Security.Tests.EFC
{
    [TestClass]
    public abstract class EFCTestBase
    {
        private Context __context;
        public Context Context => __context;

        public TestContext TestContext { get; set; }

        private EFCSecurityDataProvider _dataProviderInstance;
        internal SecurityStorage Db()
        {
            if(_dataProviderInstance == null)
                _dataProviderInstance = new EFCSecurityDataProvider(connectionString:
                    ConfigurationManager.ConnectionStrings["EF6SecurityStorage"].ConnectionString);

            var preloaded = System.Data.Entity.SqlServer.SqlProviderServices.Instance;
            return _dataProviderInstance.Db();
        }

        [TestInitialize]
        public void InitializeTest()
        {
            Db().CleanupDatabase();
            __context = CreateContext();
            Initialize();
        }

        protected abstract Context CreateContext(TextWriter traceChannel = null);

        protected virtual void Initialize()
        {
            
        }

        [TestCleanup]
        public void Finishtest()
        {
            Tools.CheckIntegrity(TestContext.TestName, Context.Security);
        }
    }
}
