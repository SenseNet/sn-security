using System;
using System.Diagnostics;
using System.Threading;
using Microsoft.Extensions.Options;
using SenseNet.Diagnostics;
using SenseNet.Security.Configuration;

namespace SenseNet.Security.Messaging
{
    internal class CommunicationMonitor
    {
        private readonly DataHandler _dataHandler;
        private readonly System.Timers.Timer _timer;

        public event EventHandler HearthBeat;

        internal CommunicationMonitor(DataHandler dataHandler, IOptions<MessagingOptions> messagingOptions)
        {
            _dataHandler = dataHandler;

            var interval = messagingOptions.Value.CommunicationMonitorRunningPeriodInSeconds * 1000.0;

            _timer = new System.Timers.Timer(interval) {Enabled = false};
            _timer.Elapsed += Timer_Elapsed;
            _timer.Disposed += Timer_Disposed;
        }

        private void Timer_Disposed(object sender, EventArgs e)
        {
            _timer.Elapsed -= Timer_Elapsed;
            _timer.Disposed -= Timer_Disposed;
        }
        private void Timer_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            Timer_Elapsed();
        }
        // for testing purposes we need a parameterless method because ElapsedEventArgs has only internal constructor
        private void Timer_Elapsed()
        {
            if (Debugger.IsAttached)
                return;

            var timerEnabled = _timer.Enabled;
            _timer.Enabled = false;

            try
            {
                HearthBeat?.Invoke(null, EventArgs.Empty);
            }
            catch (Exception ex) //logged
            {
                SnLog.WriteException(ex, EventMessage.Error.HealthCheck, EventId.RepositoryRuntime);
            }

            try
            {
                _dataHandler.CleanupSecurityActivitiesAsync(CancellationToken.None)
                    .ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch (Exception ex) //logged
            {
                SnLog.WriteException(ex, EventMessage.Error.HealthCheck, EventId.RepositoryRuntime);
            }
            finally
            {
                _timer.Enabled = timerEnabled;
            }
        }

        internal void Start()
        {
            _timer.Enabled = true;
        }
        internal void Stop()
        {
            _timer.Enabled = false;
        }

        public void Shutdown()
        {
            _timer?.Dispose();
        }
    }
}
