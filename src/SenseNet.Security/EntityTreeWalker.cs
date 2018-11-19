using System;
using System.Collections.Generic;

namespace SenseNet.Security
{
    internal class EntityTreeWalker : IEnumerable<SecurityEntity>
    {
        private readonly Stack<SecurityEntity> _stack = new Stack<SecurityEntity>();

        public EntityTreeWalker(SecurityEntity root)
        {
            if (root == null)
                throw new ArgumentNullException(nameof(root));
            _stack.Push(root);
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public IEnumerator<SecurityEntity> GetEnumerator()
        {
            while (_stack.Count > 0)
            {
                var current = _stack.Pop();
                yield return current;
                if (current.Children != null)
                    foreach (var child in current.Children)
                        _stack.Push(child);
            }
        }
    }
    internal class StopAtBreaksEntityTreeWalker : IEnumerable<SecurityEntity>
    {
        private readonly Stack<SecurityEntity> _stack = new Stack<SecurityEntity>();

        public StopAtBreaksEntityTreeWalker(SecurityEntity root)
        {
            if (root == null)
                throw new ArgumentNullException(nameof(root));
            _stack.Push(root);
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public IEnumerator<SecurityEntity> GetEnumerator()
        {
            while (_stack.Count > 0)
            {
                var current = _stack.Pop();
                if (current.IsInherited)
                {
                    yield return current;
                    if (current.Children != null)
                        foreach (var child in current.Children)
                            _stack.Push(child);
                }
            }
        }
    }
}
