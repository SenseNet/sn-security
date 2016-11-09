namespace SenseNet.Security
{
    /// <summary>
    /// Specifies an identity that can be a group or a user.
    /// Group id set and user id set must be disjunct: it is forbidden to have a group and a user with the same id.
    /// </summary>
    public interface ISecurityIdentity
    {
        /// <summary>
        /// Unique id of this instance.
        /// </summary>
        int Id { get; }
    }
}
