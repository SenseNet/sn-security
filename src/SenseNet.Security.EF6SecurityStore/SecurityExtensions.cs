using System;
using Microsoft.Extensions.DependencyInjection;
using SenseNet.Security;
using SenseNet.Security.EF6SecurityStore;
using SenseNet.Security.EF6SecurityStore.Configuration;

namespace SenseNet.Extensions.DependencyInjection
{
    /// <summary>
    /// Security extension methods.
    /// </summary>
    public static class SecurityExtensions
    {
        /// <summary>
        /// Registers <see cref="EF6SecurityDataProvider"/> as the security data provider in the service collection.
        /// </summary>
        // ReSharper disable once InconsistentNaming
        public static IServiceCollection AddEF6SecurityDataProvider(this IServiceCollection services, 
            Action<DataOptions> configure = null) 
        {
            if (configure != null)
                services.Configure(configure);

            return services.AddSingleton<ISecurityDataProvider, EF6SecurityDataProvider>();
        }
    }
}
