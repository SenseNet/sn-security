using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.EF6SecurityStore;
using SenseNet.Security.Messaging;
using SenseNet.Security.Tests.TestPortal;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SenseNet.Security.Data;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public class BigSystemStartTest
    {
        public TestContext TestContext { get; set; }

        private const string ConnectionString = "Integrated Security=SSPI;Persist Security Info=False;Initial Catalog=SenseNet.Security.Big.Test;Data Source=(local)";


        [TestMethod]
        public void SystemStartAndPreloadBigStructures()
        {
            var testCases = new[]
            {
                new { eLevel = 2, eWidth=10 },
                new { eLevel = 2, eWidth=10 },
                new { eLevel = 3, eWidth=10 },
                new { eLevel = 4, eWidth=10 },
                new { eLevel = 5, eWidth=10 },
                new { eLevel = 6, eWidth=10 },
            };
            var results = new LoadingTimeTestResult[testCases.Length];
            var i = 0;
            foreach (var testCase in testCases)
                results[i++] = TestLoadingBigStructure(testCase.eLevel, testCase.eWidth);

            var context = new Context(TestUser.User1);
        }
        private static LoadingTimeTestResult TestLoadingBigStructure(int entityMaxLevel, int entityLevelWidth)
        {
            //---- Ensure test data
            var entities = CreateTestEntities_Big(entityMaxLevel, entityLevelWidth);
            var groups = CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities };

            var timer = Stopwatch.StartNew();
            Context.StartTheSystem(new MemoryDataProvider(storage), new DefaultMessageProvider());
            timer.Stop();
            var elapsed = timer.Elapsed;

            return new LoadingTimeTestResult
            {
                Entities = entities.Count,
                Users = 0,
                Groups = groups.Count,
                Members = memberships.Count,
                Aces = aces.Count,
                LoadingTime = elapsed
            };
        }

        [DebuggerDisplay("{ToString()}")]
        class LoadingTimeTestResult
        {
            public int Entities;
            public int Users;
            public int Groups;
            public int Members;
            public int Aces;
            public TimeSpan LoadingTime;

            public override string ToString()
            {
                return String.Format("Entities: {0}, Users: {1}, Groups: {2}, Members: {3}, Aces: {4} LoadingTime: {5}",
                    Entities, Users, Groups, Members, Aces, LoadingTime);
            }
        }

        private static int _id;
        private static int _maxLevel;
        private static int _levelWidth;
        public static Dictionary<int, StoredSecurityEntity> CreateTestEntities_Big(int maxLevel, int levelWidth)
        {
            _maxLevel = maxLevel;
            _levelWidth = levelWidth;
            _id = 1;
            var storage = new Dictionary<int, StoredSecurityEntity>();

            var root = CreateEntity_Big(null, 9999999, storage);
            for (int level = 1; level < 2; level++)
                CreateTestEntities_Big(0, root, storage);

            return storage;
        }
        private static void CreateTestEntities_Big(int currentLevel, StoredSecurityEntity root, Dictionary<int, StoredSecurityEntity> storage)
        {
            if (currentLevel >= _maxLevel)
                return;
            for (int i = 0; i < _levelWidth; i++)
            {
                var entity = CreateEntity_Big(root, root.OwnerId, storage);
                CreateTestEntities_Big(currentLevel + 1, entity, storage);
            }
        }
        private static StoredSecurityEntity CreateEntity_Big(StoredSecurityEntity parentEntity, int ownerId, Dictionary<int, StoredSecurityEntity> storage)
        {
            var entity = new StoredSecurityEntity
            {
                Id = _id++,
                ParentId = parentEntity == null ? default(int) : parentEntity.Id,
                IsInherited = true,
                OwnerId = ownerId,
            };
            storage[entity.Id] = entity;

            return entity;
        }

        public static Dictionary<int, SecurityGroup> CreateTestGroups()
        {
            SecurityGroup g;
            var storage = new Dictionary<int, SecurityGroup>();

            g = new SecurityGroup(Id("G1")) { UserMemberIds = new List<int> { Id("U1"), Id("U2") } }; storage.Add(g.Id, g);
            g = new SecurityGroup(Id("G2")) { UserMemberIds = new List<int> { Id("U3"), Id("U4") } }; storage.Add(g.Id, g);
            g = new SecurityGroup(Id("G3")) { UserMemberIds = new List<int> { Id("U1"), Id("U3") } }; storage.Add(g.Id, g);
            g = new SecurityGroup(Id("G4")) { UserMemberIds = new List<int> { Id("U4") } }; storage.Add(g.Id, g);
            g = new SecurityGroup(Id("G5")) { UserMemberIds = new List<int> { Id("U5") } }; storage.Add(g.Id, g);

            return storage;
        }
        public static List<StoredAce> CreateTestAces()
        {
            var storage = new List<StoredAce>();

            storage.Add(new StoredAce { EntityId = Id("E1"), IdentityId = Id("G1"), LocalOnly = false, AllowBits = 0x0EF, DenyBits = 0x000 });
            storage.Add(new StoredAce { EntityId = Id("E1"), IdentityId = Id("U1"), LocalOnly = false, AllowBits = 0x0EE, DenyBits = 0x001 });
            storage.Add(new StoredAce { EntityId = Id("E3"), IdentityId = Id("G2"), LocalOnly = false, AllowBits = 0x0ED, DenyBits = 0x002 });
            storage.Add(new StoredAce { EntityId = Id("E5"), IdentityId = Id("G2"), LocalOnly = false, AllowBits = 0x0EC, DenyBits = 0x003 });
            storage.Add(new StoredAce { EntityId = Id("E5"), IdentityId = Id("U2"), LocalOnly = false, AllowBits = 0x0EB, DenyBits = 0x004 });
            storage.Add(new StoredAce { EntityId = Id("E50"), IdentityId = Id("G3"), LocalOnly = false, AllowBits = 0x0EA, DenyBits = 0x005 });

            return storage;
        }

        private static int Id(string name)
        {
            return Tools.GetId(name);
        }

        /*************************************************************************************************/

        //[TestMethod Timeout(10 * 60 * 1000)]
        public void EF_Performance_SystemStart_BigDatabase()
        {
            var timer = Stopwatch.StartNew();
            Context.StartTheSystem(new EF6SecurityDataProvider(connectionString: ConnectionString), new DefaultMessageProvider());
            timer.Stop();
            var ctx = new Context(TestUser.User1);
            Assert.Inconclusive("Loading time: {0}", timer.Elapsed);
        }

        //[TestMethod Timeout(10*60*1000)]
        public void EF_Performance_SystemStart_BigEntityTable()
        {
            Stopwatch timer;
            IDictionary<int, SecurityEntity> entities;

            var dataProvider = new EF6SecurityDataProvider(connectionString: ConnectionString);
            timer = Stopwatch.StartNew();
            var data = dataProvider.LoadSecurityEntities();
            timer.Stop();
            var time1 = timer.Elapsed;
            Debug.WriteLine("warmup: " + time1);


            //timer = Stopwatch.StartNew();
            ////var entities = DataHandler.LoadSecurityEntities(dataProvider);
            //entities = LoadSecurityEntities_1(dataProvider);
            //timer.Stop();
            //var time2 = timer.Elapsed;
            //Debug.WriteLine("loading time#1: " + time2);


            //timer = Stopwatch.StartNew();
            //entities = LoadSecurityEntities_2(dataProvider);
            //timer.Stop();
            //var time3 = timer.Elapsed;
            //Debug.WriteLine("loading time#2: " + time3);

            _log.Clear();
            timer = Stopwatch.StartNew();
            entities = LoadSecurityEntities_3(dataProvider);
            timer.Stop();
            var time4 = timer.Elapsed;
            Debug.WriteLine("loading time#2: " + time4);


            //Assert.Inconclusive("Loading times: {0}, {1}, {2}, {3}, {4}", time1, time2, time3, time4, _log);
            Assert.Inconclusive("Loading times: {0}, {1}, {2}", time1, time4, _log);


            // Loading times: 00:00:10.2905993, 00:02:35.7031781, 00:02:11.6167352 // #1: main lists with explicite capacity
            // Loading times: 00:00:10.2637016, 00:02:33.3550854, 00:02:07.6887293 // #2: dictionary instead of concurrent dictionary
            //                                                                            + less dictionary lookups in the building relationships
            // Loading times: 00:00:10.2887780, 00:02:33.5082941, 00:02:03.8172389
            // Load: 00:00:12.9822886, Rel: 00:01:46.5209197, Copy: 00:00:04.6075951
            // Load: 00:00:13.0581931, Rel: 00:01:46.7875856, Copy: 00:00:07.4265863
            // Load: 00:00:13.2952581, Rel: 00:01:46.8437112, Copy: 00:00:03.3409542
            // Load: 00:00:12.9505824, Rel: 00:00:02.8798472, Copy: 00:00:03.6220331 // #3: AddChild_Unsafe
            // Loading times: 00:00:09.5691147, 00:00:19.1797264, Load: 00:00:12.7218657, Rel: 00:00:02.9009923, Copy: 00:00:03.5535364







        }

        static StringBuilder _log = new StringBuilder();

        public static IDictionary<int, SecurityEntity> LoadSecurityEntities_1(ISecurityDataProvider dataProvider)
        {
            var entities = new ConcurrentDictionary<int, SecurityEntity>();
            var relations = new List<Tuple<int, int>>(); // first is Id, second is ParentId

            foreach (var storedEntity in dataProvider.LoadSecurityEntities())
            {
                var entity = new SecurityEntity
                {
                    Id = storedEntity.Id,
                    IsInherited = storedEntity.IsInherited,
                    OwnerId = storedEntity.OwnerId
                };

                entities.AddOrUpdate(entity.Id, entity, (key, val) => val);

                // memorize relations
                if (storedEntity.ParentId != default(int))
                    //entity.Parent = entities[storedEntity.ParentId];
                    relations.Add(new Tuple<int, int>(storedEntity.Id, storedEntity.ParentId));
            }

            // set parent/child relationship
            foreach (var rel in relations)
            {
                entities[rel.Item1].Parent = entities[rel.Item2];
                entities[rel.Item2].AddChild(entities[rel.Item1]);
            }

            return entities;
        }
        public static IDictionary<int, SecurityEntity> LoadSecurityEntities_2(ISecurityDataProvider dataProvider)
        {
            var timer = Stopwatch.StartNew();

            var entities = new Dictionary<int, SecurityEntity>(6400000);
            var relations = new List<Tuple<SecurityEntity, int>>(6400000); // first is Id, second is ParentId

            foreach (var storedEntity in dataProvider.LoadSecurityEntities())
            {
                var entity = new SecurityEntity
                {
                    Id = storedEntity.Id,
                    IsInherited = storedEntity.IsInherited,
                    OwnerId = storedEntity.OwnerId
                };

                entities.Add(entity.Id, entity);

                // memorize relations
                if (storedEntity.ParentId != default(int))
                    //entity.Parent = entities[storedEntity.ParentId];
                    relations.Add(new Tuple<SecurityEntity, int>(entity, storedEntity.ParentId));
            }
            _log.Append("Load: ").Append(timer.Elapsed).Append(", ");
            timer.Stop();
            timer = Stopwatch.StartNew();

            // set parent/child relationship
            foreach (var rel in relations)
            {
                var parentEntity = entities[rel.Item2];
                rel.Item1.Parent = parentEntity;
                parentEntity.AddChild(rel.Item1);
            }
            _log.Append("Rel:").Append(timer.Elapsed).Append(", ");
            timer.Stop();
            timer = Stopwatch.StartNew();

            var result = new ConcurrentDictionary<int, SecurityEntity>(entities);
            _log.Append("Copy:").Append(timer.Elapsed);

            return result;
        }
        public static IDictionary<int, SecurityEntity> LoadSecurityEntities_3(ISecurityDataProvider dataProvider)
        {
            var timer = Stopwatch.StartNew();

            var count = dataProvider.GetEstimatedEntityCount();
            var capacity = count + count / 10;

            var entities = new Dictionary<int, SecurityEntity>(capacity);
            var relations = new List<Tuple<SecurityEntity, int>>(capacity); // first is Id, second is ParentId

            foreach (var storedEntity in dataProvider.LoadSecurityEntities())
            {
                var entity = new SecurityEntity
                {
                    Id = storedEntity.Id,
                    IsInherited = storedEntity.IsInherited,
                    OwnerId = storedEntity.OwnerId
                };

                entities.Add(entity.Id, entity);

                // memorize relations
                if (storedEntity.ParentId != default(int))
                    //entity.Parent = entities[storedEntity.ParentId];
                    relations.Add(new Tuple<SecurityEntity, int>(entity, storedEntity.ParentId));
            }
            _log.Append("Load: ").Append(timer.Elapsed).Append(", ");
            timer.Stop();
            timer = Stopwatch.StartNew();

            // set parent/child relationship
            foreach (var rel in relations)
            {
                var parentEntity = entities[rel.Item2];
                rel.Item1.Parent = parentEntity;
                parentEntity.AddChild_Unsafe(rel.Item1);
            }
            _log.Append("Rel:").Append(timer.Elapsed).Append(", ");
            timer.Stop();
            timer = Stopwatch.StartNew();

            var result = new ConcurrentDictionary<int, SecurityEntity>(entities);
            _log.Append("Copy:").Append(timer.Elapsed);

            return result;
        }

    }
}
