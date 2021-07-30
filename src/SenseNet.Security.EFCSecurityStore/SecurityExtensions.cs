using System;
using Microsoft.Extensions.DependencyInjection;
using SenseNet.Security.EFCSecurityStore;
using SenseNet.Security.EFCSecurityStore.Configuration;

// ReSharper disable once CheckNamespace
namespace SenseNet.Extensions.DependencyInjection
{
    /// <summary>
    /// Security extension methods.
    /// </summary>
    public static class SecurityExtensions
    {
        /// <summary>
        /// Registers <see cref="EFCSecurityDataProvider"/> as the security data provider in the service collection.
        /// </summary>
        // ReSharper disable once InconsistentNaming
        public static IServiceCollection AddEFCSecurityDataProvider(this IServiceCollection services,
            Action<DataOptions> configure = null)
        {
            if (configure != null)
                services.Configure(configure);
            else
                services.Configure<DataOptions>(options => { });
            
            return services.AddSecurityDataProvider<EFCSecurityDataProvider>();
        }
    }
}
