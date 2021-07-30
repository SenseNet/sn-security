using System;
using Microsoft.Extensions.DependencyInjection;
using SenseNet.Security.Messaging.Msmq;

// ReSharper disable once CheckNamespace
namespace SenseNet.Extensions.DependencyInjection
{
    public static class MsmqExtensions
    {
        /// <summary>
        /// Registers the MSMQ provider as the security message provider in the service collection.
        /// </summary>
        public static IServiceCollection AddMsmqSecurityMessageProvider(this IServiceCollection services, 
            Action<MsmqOptions> configure = null)
        {
            if (configure != null)
                services.Configure(configure);
            else
                services.Configure<MsmqOptions>(msmqOptions => {});
            
            return services.AddSecurityMessageProvider<MsmqMessageProvider>();
        }
    }
}
