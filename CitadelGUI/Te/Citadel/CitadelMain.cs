/*
* Copyright © 2017 Cloudveil Technology Inc.
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using Citadel.Core.WinAPI;
using Citadel.Core.Windows.Util;
using Citadel.IPC;
using NLog;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Te.Citadel.Util;
using CloudVeil.Windows;

namespace Te.Citadel
{
    public static class CitadelMain
    {
        private static Logger MainLogger;

        private static Mutex InstanceMutex = null;

        /// <summary>
        /// </summary>
        /// <param name="args">
        /// </param>
        [STAThread]
        public static void Main(string[] args)
        {
            bool startMinimized = false;

            foreach (string arg in args)
            {
                if (arg.IndexOf("StartMinimized") != -1)
                {
                    startMinimized = true;
                }
            }

            try
            {
                if(Process.GetCurrentProcess().SessionId <= 0)
                {
                    try
                    {
                        LoggerUtil.GetAppWideLogger().Error("GUI client started in session 0 isolation. Exiting. This should not happen.");
                        Environment.Exit((int)ExitCodes.ShutdownWithoutSafeguards);
                        return;
                    }
                    catch(Exception e)
                    {
                        // XXX TODO - We can't really log here unless we do a direct to-file write.
                        Environment.Exit((int)ExitCodes.ShutdownWithoutSafeguards);
                        return;
                    }
                }
            }
            catch
            {
                // Lets assume that if we can't even read our session ID, that we're in session 0.
                Environment.Exit((int)ExitCodes.ShutdownWithoutSafeguards);
                return;
            }

            try
            {
                string appVerStr = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
                System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
                appVerStr += "." + System.Reflection.AssemblyName.GetAssemblyName(assembly.Location).Version.ToString();

                bool createdNew;
                try
                {
                    InstanceMutex = new Mutex(true, string.Format(@"Local\{0}", GuidUtility.Create(GuidUtility.DnsNamespace, appVerStr).ToString("B")), out createdNew);
                }
                catch
                {
                    // We can get access denied if SYSTEM is running this.
                    createdNew = false;
                }

                if(!createdNew)
                {
                    try
                    {
                        var thisProcess = Process.GetCurrentProcess();
                        var processes = Process.GetProcessesByName(thisProcess.ProcessName).Where(p => p.Id != thisProcess.Id);

                        foreach(Process runningProcess in processes)
                        {
                            foreach(var handle in WindowHelpers.EnumerateProcessWindowHandles(runningProcess.Id))
                            {
                                // Send window show if /StartMinimized not set.
                                if (!startMinimized)
                                {
                                    WindowHelpers.SendMessage(handle, (uint)WindowMessages.SHOWWINDOW, 9, 0);
                                }
                            }
                        }
                    }
                    catch(Exception e)
                    {
                        LoggerUtil.RecursivelyLogException(LoggerUtil.GetAppWideLogger(), e);
                    }

                    // In case we have some out of sync state where the app is running at a higher
                    // privilege level than us, the app won't get our messages. So, let's attempt an
                    // IPC named pipe to deliver the message as well.
                    try
                    {
                        using(var ipcClient = new IPCClient())
                        {
                            if (!startMinimized)
                            {
                                ipcClient.RequestPrimaryClientShowUI();
                            }

                            // Wait plenty of time before dispose to allow delivery of the msg.
                            Task.Delay(500).Wait();
                        }
                    }
                    catch(Exception e)
                    {
                        // The only way we got here is if the server isn't running, in which case we
                        // can do nothing because its beyond our domain.
                        LoggerUtil.RecursivelyLogException(LoggerUtil.GetAppWideLogger(), e);
                    }

                    // Close this instance.
                    Environment.Exit(-1);
                    return;
                }
            }
            catch(Exception e)
            {
                // The only way we got here is if the server isn't running, in which case we can do
                // nothing because its beyond our domain.
                LoggerUtil.RecursivelyLogException(LoggerUtil.GetAppWideLogger(), e);
                return;
            }

            try
            {
                Sentry.SentrySdk.Init(CompileSecrets.RavenDsn);

                MainLogger = LoggerUtil.GetAppWideLogger();
            }
            catch { }

            try
            {
                var app = new CitadelApp();
                app.InitializeComponent();
                app.Run();

                // Always release mutex.
                InstanceMutex.ReleaseMutex();
            }
            catch(Exception e)
            {
                try
                {
                    MainLogger = LoggerUtil.GetAppWideLogger();
                    LoggerUtil.RecursivelyLogException(MainLogger, e);
                }
                catch(Exception be)
                {
                    // XXX TODO - We can't really log here unless we do a direct to-file write.
                }
            }

            // No matter what, always ensure that critical flags are removed from our process before exiting.
            CriticalKernelProcessUtility.SetMyProcessAsNonKernelCritical();
        }
    }
}