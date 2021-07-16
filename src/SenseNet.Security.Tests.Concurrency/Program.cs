﻿using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using SenseNet.Security.Data;

namespace SenseNet.Security.Tests.Concurrency
{
    internal class Program
    {
        private static bool _stopped;

        // ReSharper disable once UnusedParameter.Local
        private static void Main(string[] args)
        {
            var arguments = ProgramArguments.Parse();
            if (arguments == null)
                return;
            switch (arguments.TestName.ToUpperInvariant())
            {
                case "ACL":
                    RunAcl(arguments);
                    break;
                case "SAQ":
                    RunSaq(arguments);
                    break;
                case "MOVE":
                    RunMove(arguments);
                    break;
                case "DELETE":
                    RunDelete(arguments);
                    break;
                default:
                    Console.WriteLine("Unknown test: " + arguments.TestName + ". Valid names: ACL, SAQ");
                    break;
            }
            Console.Write("Press <enter> to stop...");
            Console.ReadLine();

            _stopped = true;

            Console.Write("Press <enter> to exit...");
            Console.ReadLine();
        }


        internal static void StartTheSystem(ISecurityDataProvider securityDataProvider)
        {
            var messageSenderManager = new MessageSenderManager("asdf");
            // Call SecurityContext starter method.
            SecurityContextForConcurrencyTests.StartTheSystem(new SecurityConfiguration
            {
                SecurityDataProvider = securityDataProvider,
                MessageProvider = new DefaultMessageProvider(messageSenderManager),
                CommunicationMonitorRunningPeriodInSeconds = 31
            });

            // legacy logic
            // original line: MessageSender.Initialize("asdf");
            SecuritySystem.Instance.MessageSenderManager = messageSenderManager;
        }

        private static int Id(string name)
        {
            return Tools.GetId(name);
        }

        private static readonly Random _rnd = new Random();
        private static DateTime _started;
        private static volatile int _errors;


        private static void RunAcl(ProgramArguments arguments)
        {
            var entities = SystemStartTests.CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = SystemStartTests.CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities, Messages = new List<Tuple<int, DateTime, byte[]>>() };

            StartTheSystem(new MemoryDataProvider(storage));

            var ctx = new SecurityContextForConcurrencyTests(TestUser.User2);
            // ReSharper disable once NotAccessedVariable
            var ok = ctx.HasPermission(1, PermissionType.See);
            new AclEditor(ctx)
                .Allow(1, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(2, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(5, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(14, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(50, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(51, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(52, TestUser.User3.Id, false, PermissionType.Custom10)
                .Apply();
            // ReSharper disable once RedundantAssignment
            ok = ctx.HasPermission(52, PermissionType.See);

            _started = DateTime.UtcNow;

            Task.Run(() => AclExercise1(0));
            var _ = Enumerable.Range(1, arguments.Agents).Select(x => Task.Run(() => AclExercise(x))).ToArray();
        }
        private static void AclExercise(int id)
        {
            if (0 == id % 2)
                AclExercise1(id);
            else
                AclExercise2(id);
        }
        private static void AclExercise1(int id)
        {
            var name = "Reader-" + id;
            var ctx = new SecurityContextForConcurrencyTests(TestUser.User2);
            var count = 0;
            while (!_stopped)
            {
                Thread.Sleep(1);

                if (0 == count % 10000)
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - _started, _errors, name, count);

                var ok = ctx.HasPermission(52, PermissionType.See);

                if (!ok)
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}  ERROR", DateTime.UtcNow - _started, ++_errors, name, count);

                count++;
            }
        }
        private static void AclExercise2(int id)
        {
            var name = "Writer-" + id;
            var ctx = new SecurityContext(TestUser.User2);
            var count = 0;
            var permTypes = new[]{PermissionType.Custom01, PermissionType.Custom02};
            while (!_stopped)
            {
                Thread.Sleep(10);

                if (0 == count % 1000)
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - _started, _errors, name, count);

                var i = count % 2;
                var perm1 = permTypes[i];
                var perm2 = permTypes[1 - i];

                new AclEditor(ctx)
                    .Allow(5, TestUser.User1.Id, false, perm1)
                    .Allow(5, TestUser.User1.Id, false, perm2)
                    .Apply();

                count++;
            }
        }


        private static void RunSaq(ProgramArguments arguments)
        {
            var entities = SystemStartTests.CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = SystemStartTests.CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities, Messages = new List<Tuple<int, DateTime, byte[]>>() };

            StartTheSystem(new MemoryDataProvider(storage));

            _started = DateTime.UtcNow;

            var _ = Enumerable.Range(1, arguments.Agents).Select(x => Task.Run(() => SaqExercise(x))).ToArray();
        }
        private static void SaqExercise(int id)
        {
            // ReSharper disable once SwitchStatementMissingSomeCases
            switch (id % 3)
            {
                case 0:
                    SaqExercise0(id);
                    break;
                case 1:
                    SaqExercise1(id);
                    break;
                case 2:
                    SaqExercise2(id);
                    break;
                //case 3:
                //    SAQExercise3(id);
                //    break;
            }
        }
        private static void SaqExercise0(int id)
        {
            var name = "WaitA-" + id;
            var count = 0;
            while (!_stopped)
            {
                Thread.Sleep(10);

                if (0 == count % 100)
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - _started, _errors, name, count);

                var ctx = new SecurityContext(TestUser.User2);
                var activity = new TestWaitActivity(_rnd.Next(1, 3));
                activity.Execute(ctx, false);

                count++;
            }

        }
        private static void SaqExercise1(int id)
        {
            var name = "WaitB-" + id;
            var count = 0;
            while (!_stopped)
            {
                Thread.Sleep(10);

                if (0 == count % 100)
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - _started, _errors, name, count);

                var _ = new SecurityContext(TestUser.User2);
                var activity = new TestWaitActivity(_rnd.Next(1, 3));
                SecuritySystem.Instance.DataHandler.SaveActivity(activity);

                var method = typeof(SecurityContext).GetMethod("MessageProvider_MessageReceived", BindingFlags.Static | BindingFlags.NonPublic);
                if (method == null)
                    throw new ApplicationException("Method not found: MessageProvider_MessageReceived");

                method.Invoke(null, new object[] { null, new MessageReceivedEventArgs(activity) });
                count++;
            }

        }
        private static void SaqExercise2(int id)
        {
            var name = "WaitC-" + id;
            var count = 0;
            while (!_stopped)
            {
                Thread.Sleep(30);

                if (0 == count % 100)
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - _started, _errors, name, count);

                var _ = new SecurityContext(TestUser.User2);
                var activity = new TestWaitActivity(_rnd.Next(1, 3));
                SecuritySystem.Instance.DataHandler.SaveActivity(activity);

                count++;
            }

        }

        // ReSharper disable once UnusedParameter.Local
        private static void RunMove(ProgramArguments arguments)
        {
            var entities = SystemStartTests.CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = SystemStartTests.CreateTestAces();
            aces.Add(new StoredAce { EntityId = Id("E1"), IdentityId = Id("U3"), LocalOnly = false, AllowBits = 0x100000000, DenyBits = 0x000 });

            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities, Messages = new List<Tuple<int, DateTime, byte[]>>() };

            StartTheSystem(new MemoryDataProvider(storage));

            var ctx = new TestSecurityContext(TestUser.User3);
            var unused1 = ctx.HasPermission(52, PermissionType.Custom01);

            _started = DateTime.UtcNow;

            var unused2 = Enumerable.Range(1, 4).Select(x => Task.Run(() => MoveExercise(x))).ToArray();
        }
        private static void MoveExercise(int id)
        {
            if (id % 4 == 1)
                MoveExerciseWriter(id);
            else
                MoveExerciseReader(id);
        }
        private static void MoveExerciseWriter(int id)
        {
            var name = "Writer-" + id;
            var count = 0;
            while (!_stopped)
            {
                //Thread.Sleep(1);

                if (0 == count % 10000000)
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - _started, _errors, name, count);

                //---------------------- work

                var ctx = SecuritySystem.Instance.GeneralSecurityContext;
                var entities = ctx.Cache.Entities;
                var source = entities[3];
                var target0 = entities[1];
                var target1 = entities[52];

                var target = source.Parent == target0 ? target1 : target0;
                ctx.SecuritySystem.EntityManager.MoveEntity(source.Id, target.Id);

                //----------------------

                count++;
            }

        }
        private static void MoveExerciseReader(int id)
        {
            var name = "Reader-" + id;
            var count = 0;

                var ctx = SecuritySystem.Instance.GeneralSecurityContext;
                var entities = ctx.Cache.Entities;

            while (!_stopped)
            {
                //Thread.Sleep(1);
                //if(_rnd.Next(0, 6) == 0)
                //    Thread.Sleep(1);

                if (0 == count % 10000000)
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - _started, _errors, name, count);

                //---------------------- work

                var entity = entities[21];
                while (entity.Parent != null)
                    entity = entity.Parent;
                if (entity.Id != 1)
                    _errors++;

                //----------------------

                count++;
            }

        }

        [SuppressMessage("ReSharper", "UseObjectOrCollectionInitializer")]
        // ReSharper disable once UnusedParameter.Local
        private static void RunDelete(ProgramArguments arguments)
        {
            var entities = SystemStartTests.CreateTestEntities();
            var aces = new List<StoredAce>
            {
                new StoredAce { EntityId = Id("E1"), IdentityId = Id("U1"), LocalOnly = false, AllowBits = 0x0EF, DenyBits = 0x000 },
                new StoredAce { EntityId = Id("E4"), IdentityId = Id("U1"), LocalOnly = false, AllowBits = 0x000, DenyBits = 0x0FF }
            };
            var storage = new DatabaseStorage { Aces = aces, Memberships = new List<Membership>(), Entities = entities, Messages = new List<Tuple<int, DateTime, byte[]>>() };

            StartTheSystem(new MemoryDataProvider(storage));

            const int retryCount = 100;
            const int threadCount = 6;
            var mainWatch = Stopwatch.StartNew();

            for (var i = 0; i < retryCount; i++)
            {
                _stopped = false;

                // build the deep test entity tree
                DeleteBuildSubtree();

                var sw = Stopwatch.StartNew();

                // start permission checker loops
                var tasks = new List<Task>(); 

                // start a delete task for an entity in the middle
                tasks.Add(Task.Run(() =>
                {
                    Trace.WriteLine("SECDEL> Start DEL thread.");
                    Thread.Sleep(10);
                    var delWatch = Stopwatch.StartNew();
                    SecurityContextForConcurrencyTests.General.DeleteEntity(60);
                    delWatch.Stop();
                    Trace.WriteLine($"SECDEL> End DEL thread. Elapsed time: {delWatch.ElapsedMilliseconds}");
                    _stopped = true;
                }));

                tasks.AddRange(Enumerable.Range(1, threadCount).Select(x => Task.Run(() => DeleteCheckPermission(x))).ToList());

                Task.WaitAll(tasks.ToArray());

                sw.Stop();

                Console.WriteLine("Iteration {0}. Duration: {1} sec", i, Math.Round(sw.Elapsed.TotalSeconds));
                Trace.WriteLine($"SECDEL> Iteration {i}. Duration: {Math.Round(sw.Elapsed.TotalSeconds)} sec");
            }

            mainWatch.Stop();

            Console.WriteLine("Retry count: {0}. Errors: {1}. Elapsed time: {2}", retryCount, _errors, Math.Round(mainWatch.Elapsed.TotalSeconds));
            Console.WriteLine();
        }

        /// <summary>
        /// Create a deep tree
        /// </summary>
        private static void DeleteBuildSubtree()
        {
            var ctx = SecurityContextForConcurrencyTests.General;

            // create first entity
            ctx.CreateSecurityEntity(Id("E60"), Id("E42"), Id("U1"));

            for (var i = 61; i <= 99; i++)
            {
                ctx.CreateSecurityEntity(i, i-1, Id("U1"));
            }
        }
        private static void DeleteCheckPermission(int id)
        {
            Trace.WriteLine("SECDEL> Start check thread id " + id);
            var ctx = new SecurityContextForConcurrencyTests(TestUser.User1);
            var eid = Id("E99");
            var caught = false;
            var count = 0;

            while (!_stopped)
            {
                try
                {
                    var hp = ctx.HasPermission(eid, PermissionType.See);
                    if (hp)
                        _errors++;

                    count++;
                }
                catch (EntityNotFoundException)
                {
                    // the entity was deleted in the meantime
                    _stopped = true;
                    caught = true;
                }
            }

            Trace.WriteLine("SECDEL> End check thread id " + id + ". Catched: " + caught + ". Count: " + count);
        }
    }

    [Serializable]
    internal class TestWaitActivity : Messaging.SecurityMessages.SecurityActivity
    {
        private int _sleepInMilliseconds;

        public TestWaitActivity(int sleepInMilliseconds)
        {
            _sleepInMilliseconds = sleepInMilliseconds;
        }

        protected override void Store(SecurityContext context)
        {
            // do nothing
        }

        protected override void Apply(SecurityContext context)
        {
            // sleep
            Thread.Sleep(_sleepInMilliseconds);
        }

        internal override bool MustWaitFor(Messaging.SecurityMessages.SecurityActivity olderActivity)
        {
            return false;
        }

    }
}
