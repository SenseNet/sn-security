using System.Collections.Generic;
using System.IO;
using SenseNet.Security.Tests.TestPortal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Security.Messaging;

namespace SenseNet.Security.Tests
{
    [TestClass]
    public abstract partial class TestCases
    {
        // ReSharper disable once InconsistentNaming
        private Context __context;
        protected Context CurrentContext => __context;

        protected abstract ISecurityDataProvider GetDataProvider();
        protected abstract void CleanupMemberships();

        [TestInitialize]
        public void StartTest()
        {
            var dataProvider = GetDataProvider();
            dataProvider.DeleteEverything();
            SecurityActivityQueue._setCurrentExecutionState(new CompletionState());
            Context.StartTheSystem(dataProvider, new DefaultMessageProvider());
            __context = new Context(TestUser.User1);
        }

        /* ======================================================================= Tools */

        protected int Id(string name)
        {
            return Tools.GetId(name);
        }

        private void SetAcl(string src)
        {
            Tools.SetAcl(CurrentContext.Security, src);
        }


        private readonly Dictionary<int, TestEntity> _repository = new Dictionary<int, TestEntity>();

        private void EnsureRepository()
        {
            var u1 = TestUser.User1;

            CreateEntity("E1", null, u1);
            {
                CreateEntity("E2", "E1", u1);
                {
                    CreateEntity("E5", "E2", u1);
                    {
                        CreateEntity("E14", "E5", u1);
                        {
                            CreateEntity("E50", "E14", u1);
                            {
                                CreateEntity("E51", "E50", u1);
                                {
                                    CreateEntity("E52", "E51", u1);
                                }
                                CreateEntity("E53", "E50", u1);
                            }
                        }
                        CreateEntity("E15", "E5", u1);
                    }
                    CreateEntity("E6", "E2", u1);
                    {
                        CreateEntity("E16", "E6", u1);
                        CreateEntity("E17", "E6", u1);
                    }
                    CreateEntity("E7", "E2", u1);
                    {
                        CreateEntity("E18", "E7", u1);
                        CreateEntity("E19", "E7", u1);
                    }
                }
                CreateEntity("E3", "E1", u1);
                {
                    CreateEntity("E8", "E3", u1);
                    {
                        CreateEntity("E20", "E8", u1);
                        CreateEntity("E21", "E8", u1);
                        {
                            CreateEntity("E22", "E21", u1);
                            CreateEntity("E23", "E21", u1);
                            CreateEntity("E24", "E21", u1);
                            CreateEntity("E25", "E21", u1);
                            CreateEntity("E26", "E21", u1);
                            CreateEntity("E27", "E21", u1);
                            CreateEntity("E28", "E21", u1);
                            CreateEntity("E29", "E21", u1);
                        }
                    }
                    CreateEntity("E9", "E3", u1);
                    CreateEntity("E10", "E3", u1);
                }
                CreateEntity("E4", "E1", u1);
                {
                    CreateEntity("E11", "E4", u1);
                    CreateEntity("E12", "E4", u1);
                    {
                        CreateEntity("E30", "E12", u1);
                        {
                            CreateEntity("E31", "E30", u1);
                            {
                                CreateEntity("E33", "E31", u1);
                                CreateEntity("E34", "E31", u1);
                                {
                                    CreateEntity("E40", "E34", u1);
                                    CreateEntity("E43", "E34", u1);
                                    {
                                        CreateEntity("E44", "E43", u1);
                                        CreateEntity("E45", "E43", u1);
                                        CreateEntity("E46", "E43", u1);
                                        CreateEntity("E47", "E43", u1);
                                        CreateEntity("E48", "E43", u1);
                                        CreateEntity("E49", "E43", u1);
                                    }
                                }
                            }
                            CreateEntity("E32", "E30", u1);
                            {
                                CreateEntity("E35", "E32", u1);
                                {
                                    CreateEntity("E41", "E35", u1);
                                    {
                                        CreateEntity("E42", "E41", u1);
                                    }
                                }
                                CreateEntity("E36", "E32", u1);
                                {
                                    CreateEntity("E37", "E36", u1);
                                    {
                                        CreateEntity("E38", "E37", u1);
                                        CreateEntity("E39", "E37", u1);
                                    }
                                }
                            }
                        }
                    }
                    CreateEntity("E13", "E4", u1);
                }
            }
        }
        private TestEntity CreateEntity(string name, string parentName, TestUser owner)
        {
            var entity = new TestEntity
            {
                Id = Id(name),
                Name = name,
                OwnerId = owner?.Id ?? default(int),
                Parent = parentName == null ? null : _repository[Id(parentName)],
            };
            _repository.Add(entity.Id, entity);
            CurrentContext.Security.CreateSecurityEntity(entity);
            return entity;
        }

        private TestEntity GetRepositoryEntity(int id)
        {
            return _repository[id];
        }
    }
}
