using SenseNet.Configuration;

namespace SenseNet.Security.EFCSecurityStore.Configuration
{
    /// <summary>
    /// This configuration accessor class contains properties that are replicas 
    /// of the original properties in sensenet. They were duplicated here to
    /// let us access sensenet-specific configuration values.
    /// </summary>
    internal class Data : SnConfig
    {
        private const string DataSectionName = "sensenet/data";
        private const string SecuritySectionName = "sensenet/security";

        public static int SqlCommandTimeout { get; set; } = GetInt(DataSectionName, "SqlCommandTimeout", 120, 5);

        public static int SecurityDatabaseCommandTimeoutInSeconds { get; set; } = GetInt(SecuritySectionName,
            "SecurityDatabaseCommandTimeoutInSeconds", SqlCommandTimeout);
    }

    /// <summary>
    /// Security data options.
    /// </summary>
    public class DataOptions
    {
        /// <summary>
        /// Security database command timeout in seconds. Default: 120.
        /// </summary>
        public int SqlCommandTimeout { get; set; } = 120;

        /// <summary>
        /// Sql database connection string.
        /// </summary>
        public string ConnectionString { get; set; }
    }
}
