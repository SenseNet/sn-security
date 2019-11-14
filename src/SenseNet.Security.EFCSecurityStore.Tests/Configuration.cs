using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace SenseNet.Security.EFCSecurityStore.Tests
{
    static class Configuration
    {
        public static IConfiguration Instance { get; set; }

        internal static string GetConnectionString(this IConfiguration config)
        {
            return config["ConnectionStrings:EFCSecurityStorage"];
        }
    }
}
