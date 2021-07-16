// ReSharper disable once CheckNamespace
namespace SenseNet.Security.Tests.TestPortal
{
    public class SecurityContextForConcurrencyTests : SecurityContext
    {
        public SecurityContextForConcurrencyTests(ISecurityUser currentUser, SecuritySystem securitySystem) : base(currentUser, securitySystem) { }

        public static SecuritySystem StartTheSystem(SecurityConfiguration configuration)
        {
            var securitySystem = SecuritySystem.StartTheSystem(configuration);
            General = new SecurityContextForConcurrencyTests(securitySystem.SystemUser, securitySystem);
            return securitySystem;
        }

        internal static SecurityContextForConcurrencyTests General { get; private set; }
    }
}
