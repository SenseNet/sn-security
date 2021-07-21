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
        /// Registers <see cref="DefaultMessageProvider"/> as the security message provider in the service collection.
        /// </summary>
        public static IServiceCollection AddDefaultMessageProvider(this IServiceCollection services, IMessageSenderManager messageSenderManager = null)
        {
            return services.AddScoped<IMessageProvider>(provider =>
                new DefaultMessageProvider(messageSenderManager ?? new MessageSenderManager()));
        }
    }
}
