namespace SenseNet.Security.Tests.TestPortal
{
    public class SecurityContextForConcurrencyTests : SecurityContext
    {
        public SecurityContextForConcurrencyTests(ISecurityUser currentUser) : base(currentUser) { }

        public static new void StartTheSystem(SecurityConfiguration configuration)
        {
            SecurityContext.StartTheSystem(configuration);
            _generalContext = new SecurityContextForConcurrencyTests(SystemUser);
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
        private static SecurityContextForConcurrencyTests _generalContext;
        internal static new SecurityContextForConcurrencyTests General
        {
            get { return _generalContext; }
        }
    }
}
