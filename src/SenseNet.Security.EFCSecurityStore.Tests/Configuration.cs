﻿using Microsoft.Extensions.Configuration;

namespace SenseNet.Security.EFCSecurityStore.Tests
{
    internal static class Configuration
    {
        public static IConfiguration Instance { get; set; }

        internal static string GetConnectionString(this IConfiguration config)
        {
            return config["ConnectionStrings:EFCSecurityStorage"];
        }
    }
}
