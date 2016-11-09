using System.Collections.Generic;

namespace SenseNet.Security
{
    /// <summary>
    /// Represents a user.
    /// </summary>
    public interface ISecurityUser : ISecurityIdentity
    {
        /// <summary>
        /// Dynamic membership extensibility. Called in the permission evaluation process on the user instance of the current SecurityContext.
        /// The client application can extend the group membership of the current user in connection with an entity id.
        /// The evaluator calculates with all stored groups plus this extension every time a permission evaluation happens.
        /// </summary>
        /// <param name="entityId">Focused entity.</param>
        /// <returns>Zero, one or more group id. Null is allowed.</returns>
        IEnumerable<int> GetDynamicGroups(int entityId);
    }
}
