using System;
using Microsoft.Extensions.DependencyInjection;
using SenseNet.Security;
using SenseNet.Security.Configuration;
using SenseNet.Security.Data;
using SenseNet.Security.Messaging;

// ReSharper disable once CheckNamespace
namespace SenseNet.Extensions.DependencyInjection
{
    /// <summary>
    /// Security extension methods.
    /// </summary>
    public static class SecurityExtensions
    {
        /// <summary>
        /// Adds the security service to the collection.
        /// </summary>
        public static IServiceCollection AddSenseNetSecurity(this IServiceCollection services,
            Action<SecurityConfiguration> configureSecurity = null,
            Action<MessagingOptions> configureMessaging = null,
            Action<MessageSenderOptions> configureMessageSender = null)
        {
            // custom or default configuration
            if (configureSecurity != null)
                services.Configure(configureSecurity);
            else
                services.Configure<SecurityConfiguration>(config => { });

            if (configureMessaging != null)
                services.Configure(configureMessaging);
            else
                services.Configure<MessagingOptions>(config => { });

            services
                .AddInMemorySecurityDataProvider(DatabaseStorage.CreateEmpty())
                .AddSecurityMissingEntityHandler<MissingEntityHandler>()
                .AddDefaultSecurityMessageSenderManager(configureMessageSender)
                .AddDefaultSecurityMessageProvider()
                .AddDefaultSecurityMessageTypes()
                .AddSingleton<ISecurityMessageFormatter, SnSecurityMessageFormatter>();

            return services;
        }
        /// <summary>
        /// Registers <see cref="MemoryDataProvider"/> as the security data provider in the service collection.
        /// </summary>
        // ReSharper disable once InconsistentNaming
        public static IServiceCollection AddInMemorySecurityDataProvider(this IServiceCollection services, DatabaseStorage storage)
        {
            return services.AddSingleton<ISecurityDataProvider>(provider => new MemoryDataProvider(storage));
        }
        /// <summary>
        /// Registers a security data provider in the service collection.
        /// </summary>
        public static IServiceCollection AddSecurityDataProvider<T>(this IServiceCollection services)
            where T: class, ISecurityDataProvider
        {
            return services.AddSingleton<ISecurityDataProvider, T>();
        }

        /// <summary>
        /// Registers <see cref="DefaultMessageProvider"/> as the security message provider in the service collection.
        /// </summary>
        public static IServiceCollection AddDefaultSecurityMessageProvider(this IServiceCollection services)
        {
            return services.AddSecurityMessageProvider<DefaultMessageProvider>();
        }
        /// <summary>
        /// Registers a security message provider in the service collection.
        /// </summary>
        public static IServiceCollection AddSecurityMessageProvider<T>(this IServiceCollection services) 
            where T: class, IMessageProvider
        {
            return services.AddSingleton<IMessageProvider, T>();
        }

        /// <summary>
        /// Registers a missing entity handler in the service collection.
        /// </summary>
        public static IServiceCollection AddSecurityMissingEntityHandler<T>(this IServiceCollection services)
            where T : class, IMissingEntityHandler
        {
            return services.AddSingleton<IMissingEntityHandler, T>();
        }

        /// <summary>
        /// Registers the default message sender manager in the service collection.
        /// </summary>
        public static IServiceCollection AddDefaultSecurityMessageSenderManager(this IServiceCollection services,
            Action<MessageSenderOptions> configure = null)
        {
            return services.AddSecurityMessageSenderManager<MessageSenderManager>()
                .Configure<MessageSenderOptions>(x => { configure?.Invoke(x); });
        }
        /// <summary>
        /// Registers a message sender manager in the service collection.
        /// </summary>
        public static IServiceCollection AddSecurityMessageSenderManager<T>(this IServiceCollection services)
            where T : class, IMessageSenderManager
        {
            return services.AddSingleton<IMessageSenderManager, T>();
        }
    }
}
