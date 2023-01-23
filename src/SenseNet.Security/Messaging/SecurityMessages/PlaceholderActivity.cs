using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.Security.Messaging.SecurityMessages
{
    /// <summary>
    /// An activity arrives at ActivityQueue when the IDs of loaded activities are not discontinuous.
    /// These activities only exist in memory, they do nothing and just fill in the gaps.
    /// </summary>
    public class PlaceholderActivity : SecurityActivity
    {
        public int LastId { get; set; }

        public PlaceholderActivity(int activityId, int lastId)
        {
            this.Id = activityId;
            this.LastId = lastId;
        }

        protected override Task StoreAsync(SecurityContext context, CancellationToken cancel)
        {
            return Task.CompletedTask;
        }

        protected override void Apply(SecurityContext context)
        {
            // do nothing
        }

        internal override bool ShouldWaitFor(SecurityActivity olderActivity)
        {
            return false;
        }
    }
}
