using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security;
using SenseNet.Security.Data;

namespace SenseNet.Security.Tests
{
    public abstract class Accessor
    {
        protected object Wrapped;
        private readonly Type _wrappedType;

        protected Accessor(object wrapped)
        {
            Wrapped = wrapped;
            _wrappedType = wrapped.GetType();
        }
        internal T Invoke<T>(string name, params object[] parameters)
        {
            var method = _wrappedType.GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance);

            return (T)method.Invoke(Wrapped, parameters);
        }
        internal T GetFieldOrProperty<T>(string name)
        {
            var field = _wrappedType.GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
            return (T) field.GetValue(Wrapped);
        }
        internal T GetStaticField<T>(string name)
        {
            var field = _wrappedType.GetField(name, BindingFlags.NonPublic | BindingFlags.Static);
            return (T)field.GetValue(Wrapped);
        }
        internal void SetFieldOrProperty(string name, object value)
        {
            var field = _wrappedType.GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
            
            field.SetValue(Wrapped, value);
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

    public class AclEditorAccessor : Accessor
    {
        public AclEditorAccessor(AclEditor editor) : base(editor) { }
        public Dictionary<int, AclInfo> Acls => base.GetFieldOrProperty<Dictionary<int, AclInfo>>("_acls");
    }
}
