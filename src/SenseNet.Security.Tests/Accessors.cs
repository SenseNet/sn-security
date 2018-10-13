using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security;
using SenseNet.Security.Data;

namespace SenseNet.Security.Tests
{
    internal abstract class Accessor
    {
        protected PrivateObject _wrapped;
        private PrivateType _wrappedType;
        public Accessor(object wrapped)
        {
            _wrapped = new PrivateObject(wrapped);
            _wrappedType = new PrivateType(wrapped.GetType());
        }
        internal T Invoke<T>(string name, params object[] parameters)
        {
            return (T)_wrapped.Invoke(name, parameters);
        }
        internal T GetFieldOrProperty<T>(string name)
        {
            return (T)_wrapped.GetFieldOrProperty(name);
        }
        internal T GetStaticField<T>(string name)
        {
            return (T)_wrappedType.GetStaticField(name);
        }
        internal void SetFieldOrProperty(string name, object value)
        {
            _wrapped.SetFieldOrProperty(name, value);
        }
    }

    internal class MemoryDataProviderAccessor : Accessor
    {
        public MemoryDataProviderAccessor(MemoryDataProvider provider) : base(provider) { }

        private DatabaseStorage _storage;
        internal DatabaseStorage Storage
        {
            get
            {
                if (_storage == null)
                    _storage = base.GetStaticField<DatabaseStorage>("_storage");
                return _storage;
            }
        }
    }

    internal class AclEditorAccessor : Accessor
    {
        public AclEditorAccessor(AclEditor editor) : base(editor) { }
        internal Dictionary<int, AclInfo> Acls => base.GetFieldOrProperty<Dictionary<int, AclInfo>>("_acls");
    }

    //internal class AclCacheAccessor : Accessor
    //{
    //    public AclCacheAccessor(AclCache aclCache) : base(aclCache) { }
    //    public int Count { get { return GetFieldOrProperty<Dictionary<int, AclInfo>>("_aclTable").Count; } }
    //    public void Clear()
    //    {
    //        GetFieldOrProperty<Dictionary<int, AclInfo>>("_aclTable").Clear();
    //    }
    //}
}
