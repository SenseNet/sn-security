using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
// ReSharper disable ArrangeStaticMemberQualifier

namespace SenseNet.Security
{
    /// <summary>
    /// Represents an entity that can be used to build a tree from and have security entries.
    /// </summary>
    [DebuggerDisplay("{" + nameof(ToString) + "()}")]
    public class SecurityEntity
    {
        /// <summary>
        /// Converts the information of this instance to its equivalent string representation.
        /// </summary>
        public override string ToString()
        {
            return
                $"Id: {Id}, parent: {Parent?.Id ?? 0}, owner: {OwnerId}, {(IsInherited ? "inherited" : "BREAK")}";
        }

        /// <summary>
        /// Unique id of the entity.
        /// </summary>
        public int Id { get; internal set; }                           // 16
        /// <summary>
        /// Id of the owner user or group.
        /// </summary>
        public int OwnerId { get; internal set; }                      // 16
        /// <summary>
        /// Gets the inheritance state. True if the entity inherits the permission settings from its ancestors.
        /// </summary>
        public bool IsInherited { get; internal set; }                 //  1

        private readonly object _childrenSync = new object();

        internal List<SecurityEntity> Children { get; private set; }   // 32 * Count

        /// <summary>
        /// Parent of this entity or null.
        /// </summary>
        public SecurityEntity Parent { get; internal set; }

        /// <summary>
        /// Explicit permission entries. If this contains a value, it means this entity has explicit permission entries.
        /// Serves only test purposes, do not modify this object.
        /// </summary>
        public AclInfo Acl { get; private set; }

        internal void SetAclSafe(AclInfo acl)
        {
            if (acl == null)
            {
                // break dependency if exists
                if (Acl != null)
                    Acl.Entity = null;
            }
            else
            {
                // set dependency
                acl.Entity = this;
            }
            Acl = acl;
        }

        /// <summary>
        /// Gets the entity's level in the tree. It is the count of the items in the parent chain.
        /// </summary>
        public int Level
        {
            get
            {
                if (Parent == null)
                    return 0;
                return Parent.Level + 1;
            }
        }

        /// <summary>
        /// Used only by the initial loading process.
        /// </summary>
        [SuppressMessage("ReSharper", "InconsistentlySynchronizedField")]
        internal void AddChild_Unsafe(SecurityEntity child)
        {
            // This does not have to be thread safe as it is called only by the 
            // init process and has to be as fast as possible.
            if (Children == null)
                Children = new List<SecurityEntity>(new[] { child });
            else
                Children.Add(child);
        }
        internal void AddChild(SecurityEntity child) // called only from safe methods
        {
            lock (_childrenSync)
            {
                if (Children == null)
                {
                    Children = new List<SecurityEntity>(new[] {child});
                }
                else
                {
                    if (Children.Contains(child)) 
                        return;

                    // work with a temp list to maintain thread safety
                    var newList = new List<SecurityEntity>(Children) {child};

                    Children = newList;
                }
            }
        }
        internal void RemoveChild(SecurityEntity child) // called only from safe methods
        {
            lock (_childrenSync)
            {
                if (Children == null)
                    return;

                // work with a temp list to maintain thread safety
                var newList = new List<SecurityEntity>(Children);
                newList.Remove(child);

                Children = newList;
            }
        }

        /*************************************************************************  */
        /// <summary>
        /// True if this entity has explicit entries.
        /// </summary>
        public bool HasExplicitAcl => Acl != null;

        internal AclInfo GetFirstAcl()
        {
            var entity = this;
            while (entity != null && entity.Acl == null)
                entity = entity.Parent;
            return entity?.Acl;
        }
        [SuppressMessage("ReSharper", "ConvertIfStatementToReturnStatement")]
        internal int GetFirstAclId()
        {
            var entity = this;
            while (entity != null && entity.Acl == null)
                entity = entity.Parent;
            if (entity == null)
                return 0;
            return entity.Id;
        }
    }
}
