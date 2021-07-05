﻿using System;
using System.Timers;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Messaging
{
    /// <summary>
    /// Helper object for serializing the activity executions.
    /// </summary>
    public class SecurityActivityExecutionLock : IDisposable
    {
        private readonly SecurityActivity _activity;
        private readonly Timer _timer;

        /// <summary>
        /// Gets a value that is true if all activity operation must be executed:
        /// storing, distributing, applying in the memory. Otherwise only the memory operations are allowed.
        /// </summary>
        public bool FullExecutionEnabled { get; }

        /// <summary>
        /// Initializes a new instance of the SecurityActivityExecutionLock
        /// </summary>
        /// <param name="activity">Activity that is locked.</param>
        /// <param name="fullExecutionEnabled">If true, all activity operation must be executed:
        /// storing, distributing, applying in the memory. Otherwise only the memory operations are allowed.</param>
        public SecurityActivityExecutionLock(SecurityActivity activity, bool fullExecutionEnabled)
        {
            _activity = activity;
            FullExecutionEnabled = fullExecutionEnabled;

            var interval = Configuration.Messaging.SecurityActivityExecutionLockRefreshPeriodInSeconds * 1000.0;

            _timer = new Timer(interval) {Enabled = true};
            _timer.Elapsed += Refresh;
            _timer.Disposed += Refresh;
        }

        private void Refresh(object sender, EventArgs args)
        {
            SecuritySystem.Instance.DataHandler.RefreshSecurityActivityExecutionLock(_activity);
        }
        private void Release()
        {
            _timer.Enabled = false;
            _timer.Stop();
            _timer.Elapsed -= Refresh;
            _timer.Disposed -= Refresh;
            SecuritySystem.Instance.DataHandler.ReleaseSecurityActivityExecutionLock(_activity, FullExecutionEnabled);
        }

        private bool _disposed;
        /// <summary>
        /// Releases the lock.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _timer.Dispose();
                    Release();
                }
            }
            _disposed = true;
        }
    }
}
