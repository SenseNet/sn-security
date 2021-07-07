namespace SenseNet.Security
{
    public interface IMissingEntityHandler
    {
        /// <summary>
        /// Collects security-related information about an entity and returns true if the entity with 
        /// the specified id exists in the host application's database.
        /// This method is used by the security component when an entity seems to be missing because of
        /// concurrency reasons. The host application must provide the correct entity information here 
        /// otherwise <see cref="EntityNotFoundException"/> may occur in some scenarios under heavy load 
        /// in load balanced multi-threaded environments.
        /// </summary>
        /// <param name="entityId">Id of the missing entity.</param>
        /// <param name="parentId">Id of the missing entity's parent or 0.</param>
        /// <param name="ownerId">Id of the missing entity's owner or 0.</param>
        bool GetMissingEntity(int entityId, out int parentId, out int ownerId);
    }
    internal class MissingEntityHandler : IMissingEntityHandler
    {
        public bool GetMissingEntity(int entityId, out int parentId, out int ownerId)
        {
            parentId = ownerId = 0;
            return false;
        }
    }
}
