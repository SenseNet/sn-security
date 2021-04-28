﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;
using System.Configuration;
using SenseNet.Security.EF6SecurityStore;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class Initializer
    {
        [AssemblyInitialize]
        public static void InitializeAllTests(TestContext context)
        {
            // install db directly
            new EF6SecurityDataProvider(0, 
                    ConfigurationManager.ConnectionStrings["EF6SecurityStorage"].ConnectionString)
                .InstallDatabase();

            var _ = PermissionType.See; // pre-loads the type
        }
    }
}
