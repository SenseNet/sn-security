using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using SenseNet.Security.EF6SecurityStore;
using SenseNet.Security.EFCSecurityStore;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class Initializer
    {
        [AssemblyInitialize]
        public static void InitializeAllTests(TestContext context)
        {
            // install db directly
            new EF6SecurityDataProvider(connectionString:
                    ConfigurationManager.ConnectionStrings["EF6SecurityStorage"].ConnectionString)
                .InstallDatabase();
            new EFCSecurityDataProvider(connectionString:
                    ConfigurationManager.ConnectionStrings["EFCSecurityStorage"].ConnectionString)
                .InstallDatabase();

            var x = PermissionType.See; // preloads the type
        }
    }
}
