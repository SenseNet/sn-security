using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SenseNet.Security
{
    internal class EntityDictionary : IDictionary<int, SecurityEntity>
    {
        private List<SecurityEntity> _entities;

        public SecurityEntity this[int key]
        {
            get
            {
                var item = Lookup(key, out var index);
                if (item != null)
                    return item;
                throw new KeyNotFoundException("The given key was not present in the dictionary.");
            }
            set
            {
                var item = Lookup(key, out var index);
                if (item == null)
                    _entities.Add(value);
                else
                    _entities[index] = value;
            }
        }

        public ICollection<int> Keys => _entities.Select(x => x.Id).ToArray();

        public ICollection<SecurityEntity> Values => _entities.ToArray();

        public int Count => _entities.Count;

        public bool IsReadOnly => false;


        public EntityDictionary()
        {
            _entities = new List<SecurityEntity>();
        }
        public EntityDictionary(int capacity)
        {
            _entities = new List<SecurityEntity>(capacity);
        }


        public void Add(int key, SecurityEntity value)
        {
            _entities.Add(value); //UNDONE: Thee lookup can be slow if the list is not ordered.
        }

        public void Add(KeyValuePair<int, SecurityEntity> item)
        {
            _entities.Add(item.Value); //UNDONE: Thee lookup can be slow if the list is not ordered.
        }

        public void Clear()
        {
            _entities.Clear();
        }

        public bool Contains(KeyValuePair<int, SecurityEntity> item)
        {
            if (item.Key != item.Value.Id)
                return false;
            return ContainsKey(item.Key);
        }

        public bool ContainsKey(int key)
        {
            return Lookup(key, out var _) != null;
        }

        public void CopyTo(KeyValuePair<int, SecurityEntity>[] array, int arrayIndex)
        {
            throw new NotImplementedException();
        }

        public IEnumerator<KeyValuePair<int, SecurityEntity>> GetEnumerator()
        {
            foreach (var item in _entities)
                yield return new KeyValuePair<int, SecurityEntity>(item.Id, item);
        }

        public bool Remove(int key)
        {
            var entity = Lookup(key, out var index);

            if (entity == null)
                return false;

            _entities.RemoveAt(index);
            return true;
        }

        public bool Remove(KeyValuePair<int, SecurityEntity> item)
        {
            if (item.Key != item.Value.Id)
                return false;

            return Remove(item.Key);
        }

        public bool TryGetValue(int key, out SecurityEntity value)
        {
            value = Lookup(key, out var index);
            return value != null;
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        private class SecurityEntityComparer : IComparer<SecurityEntity>
        {
            public int Compare(SecurityEntity x, SecurityEntity y)
            {
                return x.Id.CompareTo(y.Id);
            }
        }
        private static IComparer<SecurityEntity> _entityComparer = new SecurityEntityComparer();

        private SecurityEntity Lookup(int id, out int index)
        {
            var item = new SecurityEntity { Id = id };
            index = _entities.BinarySearch(item, _entityComparer);
            return index >= 0 ? _entities[index] : null;
        }
    }
}
