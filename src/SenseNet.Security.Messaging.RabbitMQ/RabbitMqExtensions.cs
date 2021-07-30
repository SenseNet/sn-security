using System;
using Microsoft.Extensions.DependencyInjection;
using SenseNet.Security.Messaging.RabbitMQ;

// ReSharper disable once CheckNamespace
namespace SenseNet.Extensions.DependencyInjection
{
    public static class RabbitMqExtensions
    {
        /// <summary>
        /// Registers the RabbitMQ provider as the security message provider in the service collection.
        /// </summary>
        public static IServiceCollection AddRabbitMqSecurityMessageProvider(this IServiceCollection services,
            Action<RabbitMqOptions> configure = null)
        {
            if (configure != null)
                services.Configure(configure);
            else
                services.Configure<RabbitMqOptions>(msmqOptions => { });

            return services.AddSecurityMessageProvider<RabbitMQMessageProvider>();
        }
    }
}
