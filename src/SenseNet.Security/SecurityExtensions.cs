using Microsoft.Extensions.DependencyInjection;
using SenseNet.Security;
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
    }
}
