using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using SenseNet.Security.Data;

namespace SenseNet.Security.Tests.Concurrency
{
    class Program
    {
        static bool _stopped;

        static void Main(string[] args)
        {
            var arguments = ProgramArguments.Parse();
            if (arguments == null)
                return;
            switch (arguments.TestName.ToUpperInvariant())
            {
                case "ACL":
                    RunACL(arguments);
                    break;
                case "SAQ":
                    RunSAQ(arguments);
                    break;
                case "MOVE":
                    RunMOVE(arguments);
                    break;
                case "DELETE":
                    RunDELETE(arguments);
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
            MessageSender.Initialize("asdf");

            // Call SecurityContext starter method.
            SecurityContextForConcurrencyTests.StartTheSystem(new SecurityConfiguration
            {
                SecurityDataProvider = securityDataProvider,
                MessageProvider = new DefaultMessageProvider(),
                CommunicationMonitorRunningPeriodInSeconds = 31,
            });
        }

        private static int Id(string name)
        {
            return Tools.GetId(name);
        }

        private static Random _rnd = new Random();
        private static DateTime started;
        private static volatile int errors;


        private static void RunACL(ProgramArguments arguments)
        {
            var entities = SystemStartTests.CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = SystemStartTests.CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities, Messages = new List<Tuple<int, DateTime, byte[]>>() };

            StartTheSystem(new MemoryDataProvider(storage));

            var ctx = new SecurityContextForConcurrencyTests(TestUser.User2);
            var ok = ctx.HasPermission(1, PermissionType.See);
            AclEditor.Create(ctx)
                .Allow(1, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(2, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(5, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(14, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(50, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(51, TestUser.User3.Id, false, PermissionType.Custom10)
                .Allow(52, TestUser.User3.Id, false, PermissionType.Custom10)
                .Apply();
            ok = ctx.HasPermission(52, PermissionType.See);

            started = DateTime.UtcNow;

            Task.Run(() => ACLExercise1(0));
            Enumerable.Range(1, arguments.Agents).Select(x => Task.Run(() => ACLExercise(x))).ToArray();
        }
        private static void ACLExercise(int id)
        {
            if (0 == (id % 2))
                ACLExercise1(id);
            else
                ACLExercise2(id);
        }
        private static void ACLExercise1(int id)
        {
            var name = "Reader-" + id;
            var ctx = new SecurityContextForConcurrencyTests(TestUser.User2);
            var count = 0;
            var rnd = new Random();
            while (!_stopped)
            {
                Thread.Sleep(1);

                if (0 == (count % 10000))
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - started, errors, name, count);

                var ok = ctx.HasPermission(52, PermissionType.See);

                if (!ok)
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}  ERROR", DateTime.UtcNow - started, ++errors, name, count);

                count++;
            }
        }
        private static void ACLExercise2(int id)
        {
            var name = "Writer-" + id;
            var ctx = new SecurityContext(TestUser.User2);
            var count = 0;
            var permTypes = new[]{PermissionType.Custom01, PermissionType.Custom02};
            while (!_stopped)
            {
                Thread.Sleep(10);

                if (0 == (count % 1000))
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - started, errors, name, count);

                PermissionType perm1, perm2;

                var i = count % 2;
                perm1 = permTypes[i];
                perm2 = permTypes[1 - i];

                AclEditor.Create(ctx)
                    .Allow(5, TestUser.User1.Id, false, perm1)
                    .Allow(5, TestUser.User1.Id, false, perm2)
                    .Apply();

                count++;
            }
        }


        private static void RunSAQ(ProgramArguments arguments)
        {
            var entities = SystemStartTests.CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = SystemStartTests.CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities, Messages = new List<Tuple<int, DateTime, byte[]>>() };

            StartTheSystem(new MemoryDataProvider(storage));

            started = DateTime.UtcNow;

            Enumerable.Range(1, arguments.Agents).Select(x => Task.Run(() => SAQExercise(x))).ToArray();
        }
        private static void SAQExercise(int id)
        {
            switch (id % 3)
            {
                case 0:
                    SAQExercise0(id);
                    break;
                case 1:
                    SAQExercise1(id);
                    break;
                case 2:
                    SAQExercise2(id);
                    break;
                //case 3:
                //    SAQExercise3(id);
                //    break;
            }
        }
        private static void SAQExercise0(int id)
        {
            var name = "WaitA-" + id;
            var count = 0;
            while (!_stopped)
            {
                Thread.Sleep(10);

                if (0 == (count % 100))
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - started, errors, name, count);

                var ctx = new SecurityContext(TestUser.User2);
                var activity = new Test_WaitActivity(_rnd.Next(1, 3));
                activity.Execute(ctx, false);

                count++;
            }

        }
        private static void SAQExercise1(int id)
        {
            var name = "WaitB-" + id;
            var count = 0;
            while (!_stopped)
            {
                Thread.Sleep(10);

                if (0 == (count % 100))
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - started, errors, name, count);

                var ctx = new SecurityContext(TestUser.User2);
                var activity = new Test_WaitActivity(_rnd.Next(1, 3));
                DataHandler.SaveActivity(activity);
                var method = typeof(SecurityContext).GetMethod("MessageProvider_MessageReceived", BindingFlags.Static | BindingFlags.NonPublic);
                method.Invoke(null, new object[] { null, new MessageReceivedEventArgs(activity) });

                count++;
            }

        }
        private static void SAQExercise2(int id)
        {
            var name = "WaitC-" + id;
            var count = 0;
            while (!_stopped)
            {
                Thread.Sleep(30);

                if (0 == (count % 100))
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - started, errors, name, count);

                var ctx = new SecurityContext(TestUser.User2);
                var activity = new Test_WaitActivity(_rnd.Next(1, 3));
                DataHandler.SaveActivity(activity);

                count++;
            }

        }

        private static void RunMOVE(ProgramArguments arguments)
        {
            var entities = SystemStartTests.CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = SystemStartTests.CreateTestAces();
            aces.Add(new StoredAce { EntityId = Id("E1"), IdentityId = Id("U3"), LocalOnly = false, AllowBits = 0x100000000, DenyBits = 0x000 });

            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities, Messages = new List<Tuple<int, DateTime, byte[]>>() };

            StartTheSystem(new MemoryDataProvider(storage));

            var ctx = new TestSecurityContext(TestUser.User3);
            var ok = ctx.HasPermission(52, PermissionType.Custom01);

            started = DateTime.UtcNow;

            Enumerable.Range(1, 4).Select(x => Task.Run(() => MOVEExercise(x))).ToArray();
        }
        private static void MOVEExercise(int id)
        {
            if ((id % 4) == 1)
                MOVEExerciseWriter(id);
            else
                MOVEExerciseReader(id);
        }
        private static void MOVEExerciseWriter(int id)
        {
            var name = "Writer-" + id;
            var count = 0;
            while (!_stopped)
            {
                //Thread.Sleep(1);

                if (0 == (count % 10000000))
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - started, errors, name, count);

                //---------------------- work

                var ctx = SecurityContext.General;
                var entities = ctx.Cache.Entities;
                var source = entities[3];
                var target0 = entities[1];
                var target1 = entities[52];

                var target = (source.Parent == target0) ? target1 : target0;
                SecurityEntity.MoveEntity(ctx, source.Id, target.Id);

                //----------------------

                count++;
            }

        }
        private static void MOVEExerciseReader(int id)
        {
            var name = "Reader-" + id;
            var count = 0;

                var ctx = SecurityContext.General;
                var entities = ctx.Cache.Entities;

            while (!_stopped)
            {
                //Thread.Sleep(1);
                //if(_rnd.Next(0, 6) == 0)
                //    Thread.Sleep(1);

                if (0 == (count % 10000000))
                    Console.WriteLine("Running time: {0}, errors: {1}. {2} {3}", DateTime.UtcNow - started, errors, name, count);

                //---------------------- work

                var entity = entities[21];
                while (entity.Parent != null)
                    entity = entity.Parent;
                if (entity.Id != 1)
                    errors++;

                //----------------------

                count++;
            }

        }

        private static void RunDELETE(ProgramArguments arguments)
        {
            var entities = SystemStartTests.CreateTestEntities();
            var aces = new List<StoredAce>
            {
                new StoredAce { EntityId = Id("E1"), IdentityId = Id("U1"), LocalOnly = false, AllowBits = 0x0EF, DenyBits = 0x000 },
                new StoredAce { EntityId = Id("E4"), IdentityId = Id("U1"), LocalOnly = false, AllowBits = 0x000, DenyBits = 0x0FF }
            };
            var storage = new DatabaseStorage { Aces = aces, Memberships = new List<Membership>(), Entities = entities, Messages = new List<Tuple<int, DateTime, byte[]>>() };

            StartTheSystem(new MemoryDataProvider(storage));

            var retryCount = 100;
            var threadCount = 6;
            var mainWatch = Stopwatch.StartNew();

            for (var i = 0; i < retryCount; i++)
            {
                _stopped = false;

                // build the deep test enity tree
                DELETEBuildSubtree();

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
                    Trace.WriteLine(string.Format("SECDEL> End DEL thread. Elapsed time: {0}", delWatch.ElapsedMilliseconds));
                    _stopped = true;
                }));

                tasks.AddRange(Enumerable.Range(1, threadCount).Select(x => Task.Run(() => DELETECheckPermission(x))).ToList());

                Task.WaitAll(tasks.ToArray());

                sw.Stop();

                Console.WriteLine("Iteration {0}. Duration: {1} sec", i, Math.Round(sw.Elapsed.TotalSeconds));
                Trace.WriteLine(string.Format("SECDEL> Iteration {0}. Duration: {1} sec", i, Math.Round(sw.Elapsed.TotalSeconds)));
            }

            mainWatch.Stop();

            Console.WriteLine("Retry count: {0}. Errors: {1}. Elapsed time: {2}", retryCount, errors, Math.Round(mainWatch.Elapsed.TotalSeconds));
            Console.WriteLine();
        }

        /// <summary>
        /// Create a deep tree
        /// </summary>
        private static void DELETEBuildSubtree()
        {
            var ctx = SecurityContextForConcurrencyTests.General;

            // create first entity
            ctx.CreateSecurityEntity(Id("E60"), Id("E42"), Id("U1"));

            for (var i = 61; i <= 99; i++)
            {
                ctx.CreateSecurityEntity(i, i-1, Id("U1"));
            }
        }
        private static void DELETECheckPermission(int id)
        {
            Trace.WriteLine("SECDEL> Start check thread id " + id);
            var ctx = new SecurityContextForConcurrencyTests(TestUser.User1);
            var eid = Id("E99");
            var catched = false;
            var count = 0;

            while (!_stopped)
            {
                try
                {
                    var hp = ctx.HasPermission(eid, PermissionType.See);
                    if (hp)
                        errors++;

                    count++;
                }
                catch (EntityNotFoundException)
                {
                    // the entity was deleted in the meantime
                    _stopped = true;
                    catched = true;
                }
            }

            Trace.WriteLine("SECDEL> End check thread id " + id + ". Catched: " + catched + ". Count: " + count);
        }
    }

    [Serializable]
    internal class Test_WaitActivity : SenseNet.Security.Messaging.SecurityMessages.SecurityActivity
    {
        int _sleepInMillisconds;

        public Test_WaitActivity(int sleepInMillisconds)
        {
            _sleepInMillisconds = sleepInMillisconds;
        }

        protected override void Store(SecurityContext context)
        {
            // do nothing
        }

        protected override void Apply(SecurityContext context)
        {
            // sleep
            Thread.Sleep(_sleepInMillisconds);
        }

        internal override bool MustWaitFor(SenseNet.Security.Messaging.SecurityMessages.SecurityActivity olderActivity)
        {
            return false;
        }

    }
}
