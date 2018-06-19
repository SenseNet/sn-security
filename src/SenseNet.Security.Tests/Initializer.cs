﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Tests.TestPortal;
using System;
using System.Collections.Generic;
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
            var dbProvider = new EFCSecurityDataProvider();
            dbProvider.InstallDatabase();

            var x = PermissionType.See; // preloads the type
        }
    }
}
