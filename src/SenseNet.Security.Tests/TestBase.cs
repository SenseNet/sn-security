using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Diagnostics;
using SenseNet.Security.Tests.TestPortal;

namespace SenseNet.Security.Tests
{
    public abstract class TestBase
    {
        private SnTrace.Operation _snTraceOperation;
        public void _StartTest(TestContext testContext)
        {
            //if (!SnTrace.SnTracers.Any(x => x is SnDebugViewTracer))
            //    SnTrace.SnTracers.Add(new SnDebugViewTracer());
            if (!SnTrace.SnTracers.Any(x => x is SnFileSystemTracer))
                SnTrace.SnTracers.Add(new SnFileSystemTracer());
            SnTrace.EnableAll();
            SnTrace.SecurityQueue.Enabled = false;

            _snTraceOperation =
                SnTrace.Test.StartOperation(
                    $"TESTMETHOD: {testContext.FullyQualifiedTestClassName}.{testContext.TestName}");
        }
        public void _FinishTest(TestContext testContext)
        {
            if (_snTraceOperation != null)
            {
                _snTraceOperation.Successful = true;
                _snTraceOperation.Dispose();
            }
            SnTrace.Flush();
        }

        /* ============================================================================================== */

        public int GetId(string name)
        {
            if (name[0] == 'G')
                return TestGroup.GetId(byte.Parse(name.Substring(1)));
            if (name[0] == 'U')
                return TestUser.GetId(byte.Parse(name.Substring(1)));
            if (name[0] == 'E')
                return TestEntity.GetId(byte.Parse(name.Substring(1)));
            throw new NotSupportedException("Invalid name: " + name);
        }

        internal void SetAcl(SecurityContext context, string src)
        {
            // "+E1|Normal|+U1:____++++,+G1:____++++"
            var a = src.Split('|');
            var inherits = a[0][0] == '+';
            var b = a[0].Substring(1);
            if (b.Contains(','))
                throw new NotSupportedException("DO NOT PASS OWNER INFORMATION");
            var entityId = GetId(b);
            SetAcl(context, entityId, inherits, src.Substring(a[0].Length + 1));
        }
        private void SetAcl(SecurityContext context, int entityId, bool isInherited, string src)
        {
            // "+U1:____++++,+G1:____++++"
            var entity = context.GetSecurityEntity(entityId);

            var aclInfo = new AclInfo(entityId) { Entries = src.Split(',').Select(CreateAce).ToList() };

            var @break = false;
            var undoBreak = false;
            if (entity.IsInherited && !isInherited)
                @break = true;
            if (!entity.IsInherited && isInherited)
                undoBreak = true;
            context.SetAcls(
                new[] { aclInfo },
                @break ? new List<int> { entityId } : new List<int>(),
                undoBreak ? new List<int> { entityId } : new List<int>()
                );
        }
        private AceInfo CreateAce(string src)
        {
            // "Normal|+U1:____++++
            var segments = src.Split('|');

            Enum.TryParse<EntryType>(segments[0], true, out var entryType);

            var localOnly = segments[1][0] != '+';
            var a = segments[1].Substring(1).Split(':');

            ParsePermissions(a[1], out var allowBits, out var denyBits);
            return new AceInfo
            {
                EntryType = entryType,
                LocalOnly = localOnly,
                IdentityId = GetId(a[0]),
                AllowBits = allowBits,
                DenyBits = denyBits
            };
        }

        internal void ParsePermissions(string src, out ulong allowBits, out ulong denyBits)
        {
            //+_____-____++++
            const ulong mask = 1ul;
            allowBits = denyBits = 0;
            for (var i = src.Length - 1; i >= 0; i--)
            {
                var c = src[i];
                if (c == '+')
                    allowBits |= mask << src.Length - i - 1;
                if (c == '-')
                    denyBits |= mask << src.Length - i - 1;
            }
        }

    }
}
