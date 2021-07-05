using System;
using System.Diagnostics;
using SenseNet.Diagnostics;

namespace SenseNet.Security.Messaging
{
    internal class CommunicationMonitor
    {
        private System.Timers.Timer _timer;

        internal CommunicationMonitor()
        {
            var interval = Configuration.Messaging.CommunicationMonitorRunningPeriodInSeconds * 1000.0;

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
                SecuritySystem.Instance.SecurityActivityQueue.HealthCheck();
                SecuritySystem.Instance.DataHandler.CleanupSecurityActivities();
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
