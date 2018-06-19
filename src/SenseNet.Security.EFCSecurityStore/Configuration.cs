using System.Data.Entity.Migrations;

namespace SenseNet.Security.EFCSecurityStore
{
    /// <summary>
    /// Migration class for switching OFF automatic database migration. Do not delete this class!
    /// </summary>
    internal sealed class MigrationsConfiguration : DbMigrationsConfiguration<SecurityStorage>
    {
        public MigrationsConfiguration()
        {
            AutomaticMigrationsEnabled = false;
        }
    }
}
