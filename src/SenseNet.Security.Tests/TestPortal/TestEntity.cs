namespace SenseNet.Security.Tests.TestPortal
{
    public class TestEntity
    {
        public int Id { get; set; }
        public int OwnerId { get; set; }
        public string Name { get; set; }
        public int ParentId { get; set; }
        private TestEntity _parent;
        public TestEntity Parent
        {
            get { return _parent; }
            set { _parent = value; ParentId = value == null ? default : value.Id; }
        }

        //========================================================================================

        internal static int GetId(byte index)
        {
            return index;
        }

    }
}
