// ReSharper disable once CheckNamespace
namespace SenseNet.Security.Tests.TestPortal
{
    public class SecurityContextForConcurrencyTests : SecurityContext
    {
        public SecurityContextForConcurrencyTests(ISecurityUser currentUser) : base(currentUser) { }

        public new static void StartTheSystem(SecurityConfiguration configuration)
        {
            SecuritySystem.StartTheSystem(configuration);
            General = new SecurityContextForConcurrencyTests(SystemUser);
        }

        /*********************** Low level evaluator API **********************/
        public new bool HasPermission(int entityId, params PermissionTypeBase[] permissions)
        {
            return base.HasPermission(entityId, permissions);
        }

        /*********************** Low level structure API **********************/
        public new void CreateSecurityEntity(int entityId, int parentEntityId, int ownerId)
        {
            base.CreateSecurityEntity(entityId, parentEntityId, ownerId);
        }
        public new void DeleteEntity(int entityId)
        {
            base.DeleteEntity(entityId);
        }

        /***************** General context for built in system user ***************/
        internal new static SecurityContextForConcurrencyTests General { get; private set; }
    }
}
