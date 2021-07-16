// ReSharper disable once CheckNamespace
namespace SenseNet.Security.Tests.TestPortal
{
    public class SecurityContextForConcurrencyTests : SecurityContext
    {
        public SecurityContextForConcurrencyTests(ISecurityUser currentUser) : base(currentUser) { }

        public static void StartTheSystem(SecurityConfiguration configuration)
        {
            SecuritySystem.StartTheSystem(configuration);
            General = new SecurityContextForConcurrencyTests(SecuritySystem.Instance.SystemUser);
        }

        internal static SecurityContextForConcurrencyTests General { get; private set; }
    }
}
