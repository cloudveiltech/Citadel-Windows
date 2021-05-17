﻿/*
* Copyright © 2017-Present Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using CitadelCore.Extensions;
using CitadelCore.Net.Proxy;
using CitadelCore.Windows.WinAPI;
using Filter.Platform.Common.Util;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using WinDivertSharp;
using WinDivertSharp.WinAPI;

namespace CitadelCore.Windows.Diversion
{
    public class WindowsDiverter
    {
        private NLog.Logger m_logger;

        /// <summary>
        /// The local IPV4 port that the filtering proxy server is listening for HTTP connections on.
        /// </summary>
        private ushort m_v4HttpProxyPort;

        /// <summary>
        /// The local IPV4 port that the filtering proxy server is listening for HTTPS connections on.
        /// </summary>
        private ushort m_v4HttpsProxyPort;

        /// <summary>
        /// The local IPV6 port that the filtering proxy server is listening for HTTP connections on.
        /// </summary>
        private ushort m_v6HttpProxyPort;

        /// <summary>
        /// The local IPV6 port that the filtering proxy server is listening for HTTPS connections on.
        /// </summary>
        private ushort m_v6HttpsProxyPort;

        /// <summary>
        /// Used for tracking which IPV4 TCP connections ought to be forced through the proxy server.
        /// We use the local port of TCP connections as the index to this array.
        /// </summary>
        private readonly byte[] m_v4ShouldFilter = new byte[ushort.MaxValue];

        /// <summary>
        /// Used for tracking which IPV6 TCP connections ought to be forced through the proxy server.
        /// We use the local port of TCP connections as the index to this array.
        /// </summary>
        private readonly byte[] m_v6ShouldFilter = new byte[ushort.MaxValue];

        /// <summary>
        /// Used for keeping track of the local port that we are to return packets to after filtering.
        /// </summary>
        /// <remarks>
        /// In moving toward port-independent filtering, we need to be able to keep track of the
        /// original port that a connection was intercepted on. This way, we can make sure we route
        /// filtered connection data back to the right local port.
        /// </remarks>
        private readonly ushort[] m_v4ReturnPorts = new ushort[ushort.MaxValue];

        /// <summary>
        /// Used for keeping track of the local port that we are to return packets to after filtering.
        /// </summary>
        /// <remarks>
        /// In moving toward port-independent filtering, we need to be able to keep track of the
        /// original port that a connection was intercepted on. This way, we can make sure we route
        /// filtered connection data back to the right local port.
        /// </remarks>
        private readonly ushort[] m_v6ReturnPorts = new ushort[ushort.MaxValue];

        /// <summary>
        /// Keeps track of user-supplied hints about whether or not a filtered connection is
        /// encrypted. Specific to IPv6 connections.
        /// </summary>
        private readonly bool[] m_v4EncryptionHints = new bool[ushort.MaxValue];

        /// <summary>
        /// Keeps track of user-supplied hints about whether or not a filtered connection is
        /// encrypted. Specific to IPv4 connections.
        /// </summary>
        private readonly bool[] m_v6EncryptionHints = new bool[ushort.MaxValue];

        /// <summary>
        /// Constant for port 443 TCP aka HTTPS.
        /// </summary>
        private readonly ushort m_httpsStandardPort;

        /// <summary>
        /// Constant for port 443 TCP aka HTTPS alt port.
        /// </summary>
        private readonly ushort m_httpsAltPort;

        /// <summary>
        /// Our process ID. We use this to ignore packets originating from within our own software.
        /// </summary>
        private readonly ulong m_thisPid = (ulong)Process.GetCurrentProcess().Id;

        /// <summary>
        /// Flag for the main processing loop.
        /// </summary>
        private volatile bool m_running = false;

        /// <summary>
        /// For synchronizing startup and shutdown.
        /// </summary>
        private readonly object m_startStopLock = new object();

        /// <summary>
        /// WinDivert driver handle.
        /// </summary>
        private IntPtr m_diversionHandle = IntPtr.Zero;

        /// <summary>
        /// Collection of threads running against the WinDivert driver.
        /// </summary>
        private List<Thread> m_diversionThreads;

        private static readonly IntPtr s_InvalidHandleValue = new IntPtr(-1);

        /// <summary>
        /// Gets whether or not the diverter is currently active.
        /// </summary>
        public bool IsRunning
        {
            get
            {
                return m_running;
            }
        }

        /// <summary>
        /// Optional callback that allows the user to determine if a specific binary should have its
        /// traffic sent through the filter, which implicitly permits network access.
        /// </summary>
        public FirewallCheckCallback ConfirmDenyFirewallAccess
        {
            get;
            set;
        }

        /// <summary>
        /// Constructs a new WindowsDiverter instance.
        /// </summary>
        /// <param name="v4httpProxyPort">
        /// The IPV4 port that the filtering proxy server is listening for HTTP connections on.
        /// </param>
        /// <param name="v4httpsProxyPort">
        /// The IPV4 port that the filtering proxy server is listening for HTTPS connections on.
        /// </param>
        /// <param name="v6httpProxyPort">
        /// The IPV6 port that the filtering proxy server is listening for HTTP connections on.
        /// </param>
        /// <param name="v6httpsProxyPort">
        /// The IPV6 port that the filtering proxy server is listening for HTTPS connections on.
        /// </param>
        public WindowsDiverter()
        {
            m_logger = LoggerUtil.GetAppWideLogger();

            // WinDivertSharp does not do automatic byte order swapping like our old build-in version
            // did. So, we'll do the swap to network order immediately, if applicable (which it
            // always should be) and then move on in life.

            if (BitConverter.IsLittleEndian)
            {
                m_httpsAltPort = (ushort)IPAddress.HostToNetworkOrder((short)8443);
                m_httpsStandardPort = (ushort)IPAddress.HostToNetworkOrder((short)443);
            }
            else
            {
                m_httpsAltPort = ((ushort)8443);
                m_httpsStandardPort = ((ushort)443);
            }
        }

        public void UpdatePorts(ushort v4httpProxyPort, ushort v4httpsProxyPort, ushort v6httpProxyPort, ushort v6httpsProxyPort)
        {
            m_v4HttpProxyPort = (ushort)IPAddress.HostToNetworkOrder((short)v4httpProxyPort);
            m_v4HttpsProxyPort = (ushort)IPAddress.HostToNetworkOrder((short)v4httpsProxyPort);

            m_v6HttpProxyPort = (ushort)IPAddress.HostToNetworkOrder((short)v6httpProxyPort);
            m_v6HttpsProxyPort = (ushort)IPAddress.HostToNetworkOrder((short)v6httpsProxyPort);
        }

        public delegate void StartEventHandler();

        /// <summary>
        /// Starts the packet diversion with the given number of threads.
        /// </summary>
        /// <param name="numThreads">
        /// The number of threads to use for diversion. If equal to or less than zero, will default
        /// to Environment.ProcessorCount.
        /// </param>
        /// <remarks>
        /// The number of threads ought not to exceed Environment.ProcessorCount but this is not
        /// enforced with a bounds check.
        /// </remarks>
        public void Start(int numThreads, StartEventHandler startHandler = null)
        {
            lock (m_startStopLock)
            {
                if (m_running)
                {
                    return;
                }

                if (numThreads <= 0)
                {
                    numThreads = Environment.ProcessorCount;
                }

                m_diversionThreads = new List<Thread>();

                string mainFilterString = "outbound and (tcp or (udp and (udp.DstPort == 80 || udp.DstPort == 443)))";
                m_diversionHandle = WinDivert.WinDivertOpen(mainFilterString, WinDivertLayer.Network, -1000, 0);

                if (m_diversionHandle == s_InvalidHandleValue || m_diversionHandle == IntPtr.Zero)
                {
                    // Invalid handle value.
                    throw new Exception(string.Format("Failed to open main diversion handle. Got Win32 error code {0}.", Marshal.GetLastWin32Error()));
                }

  

                // Set everything to maximum values.
                WinDivert.WinDivertSetParam(m_diversionHandle, WinDivertParam.QueueLen, 16384);
                WinDivert.WinDivertSetParam(m_diversionHandle, WinDivertParam.QueueTime, 8000); 
                WinDivert.WinDivertSetParam(m_diversionHandle, WinDivertParam.QueueSize, 33554432);

                m_running = true;

                for (int i = 0; i < numThreads; ++i)
                {
                    m_diversionThreads.Add(new Thread(() =>
                    {
                        RunDiversion();
                    }));

                    m_diversionThreads.Last().Start();
                }

                startHandler?.Invoke();
            }
        }

        private unsafe void RunDiversion()
        {
            var packet = new WinDivertBuffer();

            var addr = new WinDivertAddress();

            uint recvLength = 0;

            NativeOverlapped recvOverlapped;

            IntPtr recvEvent = IntPtr.Zero;
            recvEvent = WinDivertSharp.WinAPI.Kernel32.CreateEvent(IntPtr.Zero, false, false, IntPtr.Zero);

            if (recvEvent == IntPtr.Zero || recvEvent == new IntPtr(-1))
            {
                m_logger.Error("Failed to initialize receive IO event.");
                return;
            }

            uint recvAsyncIoLen = 0;

            bool isLocalIpv4 = false;
            bool modifiedPacket = false;
            bool dropPacket = false;

            Span<byte> payloadBufferPtr = null;

            while (m_running)
            {
                try
                {
                    payloadBufferPtr = null;

                    recvLength = 0;
                    addr.Reset();
                    modifiedPacket = false;
                    dropPacket = false;
                    isLocalIpv4 = false;
                    recvAsyncIoLen = 0;

                    recvOverlapped = new NativeOverlapped();
                    WinAPI.Kernel32.ResetEvent(recvEvent);                    

                    recvOverlapped.EventHandle = recvEvent;

                    #region Packet Reading Code

                    uint addrLen = (uint)sizeof(WinDivertAddress);
                    if (!WinDivert.WinDivertRecvEx(m_diversionHandle, packet, 0, out recvLength, out addr, ref addrLen, ref recvOverlapped))
                    {
                        var error = Marshal.GetLastWin32Error();

                        // 997 == ERROR_IO_PENDING
                        if (error != 997)
                        {
                            m_logger.Warn(string.Format("Unknown IO error ID {0}while awaiting overlapped result.", error));
                            continue;
                        }

                        // 258 == WAIT_TIMEOUT
                        while (m_running && WinDivertSharp.WinAPI.Kernel32.WaitForSingleObject(recvEvent, 1000) == (uint)WaitForSingleObjectResult.WaitTimeout)
                        {
                            
                        }

                        if (!WinDivertSharp.WinAPI.Kernel32.GetOverlappedResult(m_diversionHandle, ref recvOverlapped, ref recvAsyncIoLen, false))
                        {
                            m_logger.Warn("Failed to get overlapped result.");
                            continue;
                        }

                        recvLength = recvAsyncIoLen;
                    }

                    #endregion Packet Reading Code


                    WinDivertParseResult parseResult = null;
                    if (addr.Outbound)
                    {
                        parseResult = WinDivert.WinDivertHelperParsePacket(packet, recvLength);

                        if(parseResult.UdpHeader != null)
                        {
                            var connInfo = GetLocalPacketInfo(parseResult.UdpHeader->SrcPort, parseResult.IPv4Header->SrcAddr);
                            if (connInfo != null)
                            {
                                var procPath = connInfo.OwnerProcessPath.Length > 0 ? connInfo.OwnerProcessPath : "SYSTEM";
                                var firewallRequest = new FirewallRequest(procPath, parseResult.UdpHeader->SrcPort, parseResult.UdpHeader->DstPort, connInfo.OwnerPid);
                                var response = ConfirmDenyFirewallAccess?.Invoke(firewallRequest);
                                if (response.Action == FirewallAction.BlockInternetForApplication || response.Action == FirewallAction.FilterApplication)
                                {
                                    dropPacket = true;
                                    m_logger.Info("Blocking UDP traffic from " + connInfo.OwnerProcessPath);
                                }
                                else
                                {
                                    m_logger.Info("Allowing UDP traffic from " + connInfo.OwnerProcessPath);
                                }
                            } 
                            else
                            {
                                m_logger.Info("Blocking UDP traffic from unknown process");
                                dropPacket = true;
                            }
                        }

                        #region New TCP Connection Detection
                        if (parseResult.TcpHeader != null && parseResult.TcpHeader->Syn > 0)
                        {
                            // Brand new outbound connection. Grab the PID of the process holding this
                            // port and map it.
                            if (parseResult.IPv4Header != null)
                            {
                                var connInfo = GetLocalPacketInfo(parseResult.TcpHeader->SrcPort, parseResult.IPv4Header->SrcAddr);

                                HandleNewTcpConnection(connInfo, parseResult.TcpHeader, false);

                                // Handle the special case of entirely blocking internet for this application/port.
                                if (Volatile.Read(ref m_v4ShouldFilter[parseResult.TcpHeader->SrcPort]) == (int)FirewallAction.BlockInternetForApplication)
                                {
                                    dropPacket = true;
                                }
                            }

                            if (parseResult.IPv6Header != null)
                            {
                                var connInfo = GetLocalPacketInfo(parseResult.TcpHeader->SrcPort, parseResult.IPv6Header->SrcAddr);

                                HandleNewTcpConnection(connInfo, parseResult.TcpHeader, true);

                                // Handle the special case of entirely blocking internet for this application/port.
                                if (Volatile.Read(ref m_v6ShouldFilter[parseResult.TcpHeader->SrcPort]) == (int)FirewallAction.BlockInternetForApplication)
                                {
                                    dropPacket = true;
                                }
                            }
                        }

                        // Now that we've processed any potentially new connections, let's see if the
                        // packet belongs to an existing flow that was marked to be blocked.

                        // Check if this packet belongs to an IPV4 flow marked for blocking.
                        if (parseResult.IPv4Header != null && parseResult.TcpHeader != null)
                        {
                            int srcPortAction = Volatile.Read(ref m_v4ShouldFilter[parseResult.TcpHeader->SrcPort]);

                            // Handle the special case of entirely blocking internet for this application/port.
                            if (srcPortAction == (int)FirewallAction.BlockInternetForApplication)
                            {
                                dropPacket = true;
                            }
                        }

                        // Check if this packet belongs to an IPV6 flow marked for blocking.
                        if (!dropPacket && parseResult.IPv6Header != null && parseResult.TcpHeader != null)
                        {
                            int srcPortAction = Volatile.Read(ref m_v6ShouldFilter[parseResult.TcpHeader->SrcPort]);

                            // Handle the special case of entirely blocking internet for this application/port.
                            if (srcPortAction == (int)FirewallAction.BlockInternetForApplication)
                            {
                                dropPacket = true;
                            }
                        }

                        #endregion New TCP Connection Detection

                        // I put the checks for ipv4 and ipv6 as a double if statement rather than an
                        // else if because I'm not sure how that would affect dual-mode sockets. Perhaps
                        // it's possible for both headers to be defined. Probably not, but since I don't
                        // know, I err on the side of awesome, or uhh, something like that.

                        // We check local packets for TOR/SOCKS packets here. However, if we don't find
                        // something we want to block on local addresses, then we want to skip these for
                        // the rest of the filtering and just let them through.

                        if (dropPacket == false && parseResult.IPv4Header != null && parseResult.TcpHeader != null)
                        {
                            // Let's explain the weird arcane logic here. First, we check if the current
                            // flow should even be filtered. We do this, because there's a good chance
                            // that this flow belongs to our proxy's connections, which we never want to
                            // filter. If we didn't check this, then we would end up setting the
                            // isLocalIpv4 flag to true on every single one of our proxy's connections,
                            // and clients would never get packets ever because with that flag set, the
                            // direction of the packets wouldn't be sorted.
                            //
                            // So, we check this, ensure it's actually something we want to filter. Then,
                            // we check if the packet is destined for a local address. We set the flag
                            // accordingly, and if true, then we will allow these packets to go out uninterrupted.
                            //
                            // If false, who cares. Regardless of true or false, we check to see if this
                            // is a TOR/SOCKS4/5 proxy CONNECT, and drop it if it is.
                            //
                            // Also note, by letting local/private address destined packets go, we also
                            // solve the problem of private TLS connections using private TLS self signed
                            // certs, such as logging into one's router. If we didn't do this check and
                            // let these through, we would break such connections.

                            if (Volatile.Read(ref m_v4ShouldFilter[parseResult.TcpHeader->SrcPort]) == (int)FirewallAction.FilterApplication)
                            {
                                isLocalIpv4 = parseResult.IPv4Header->DstAddr.IsPrivateIpv4Address();

                                if (isLocalIpv4)
                                {
#if !ENGINE_NO_BLOCK_TOR
                                    byte[] payload = null;
                                    if (payloadBufferPtr != null && payloadBufferPtr.Length > 0)
                                    {
                                        payload = payloadBufferPtr.ToArray();

                                        if (payload.IsSocksProxyConnect())
                                        {
                                            m_logger.Info("Blocking SOCKS proxy connect.");
                                            continue;
                                        }
                                    }
#endif
                                }
                            }
                        }

                        if (dropPacket == false && !isLocalIpv4)
                        {
                            if (parseResult.IPv4Header != null && parseResult.TcpHeader != null)
                            {
                                if (parseResult.TcpHeader->SrcPort == m_v4HttpProxyPort || parseResult.TcpHeader->SrcPort == m_v4HttpsProxyPort)
                                {
                                    // Means that the data is originating from our proxy in response to a
                                    // client's request, which means it was originally meant to go
                                    // somewhere else. We need to reorder the data such as the src and
                                    // destination ports and addresses and divert it back inbound, so it
                                    // appears to be an inbound response from the original external server.

                                    modifiedPacket = true;

                                    parseResult.TcpHeader->SrcPort = Volatile.Read(ref m_v4ReturnPorts[parseResult.TcpHeader->DstPort]);
                                    addr.Outbound = false;

                                    var dstIp = parseResult.IPv4Header->DstAddr;
                                    parseResult.IPv4Header->DstAddr = parseResult.IPv4Header->SrcAddr;
                                    parseResult.IPv4Header->SrcAddr = dstIp;
                                }
                                else
                                {

                                    // This means outbound traffic has been captured that we know for
                                    // sure is not coming from our proxy in response to a client, but we
                                    // don't know that it isn't the upstream portion of our proxy trying
                                    // to fetch a response on behalf of a connected client. So, we need
                                    // to check if we have a cached result for information about the
                                    // binary generating the outbound traffic for two reasons.
                                    //
                                    // First, we need to ensure that it's not us, obviously. Secondly, we
                                    // need to ensure that the binary has been granted firewall access to
                                    // generate outbound traffic.

                                    if (Volatile.Read(ref m_v4ShouldFilter[parseResult.TcpHeader->SrcPort]) == (int)FirewallAction.FilterApplication)
                                    {
                                        modifiedPacket = true;

                                        // If the process was identified as a process that is permitted
                                        // to access the internet, and is not a system process or
                                        // ourselves, then we divert its packets back inbound to the
                                        // local machine, changing the destination port appropriately.
                                        var dstAddress = parseResult.IPv4Header->DstAddr;

                                        parseResult.IPv4Header->DstAddr = parseResult.IPv4Header->SrcAddr;
                                        parseResult.IPv4Header->SrcAddr = dstAddress;

                                        addr.Outbound = false;

                                        Volatile.Write(ref m_v4ReturnPorts[parseResult.TcpHeader->SrcPort], parseResult.TcpHeader->DstPort);

                                        GoproxyWrapper.GoProxy.Instance.SetDestPortForLocalPort(parseResult.TcpHeader->SrcPort, parseResult.TcpHeader->DstPort);

                                        // Unless we know for sure this is an encrypted connection via
                                        // the HTTP port, we should always default to sending to the
                                        // non-encrypted listener.
                                        var encrypted = Volatile.Read(ref m_v4EncryptionHints[parseResult.TcpHeader->SrcPort]);

                                        parseResult.TcpHeader->DstPort = encrypted ? m_v4HttpsProxyPort : m_v4HttpProxyPort;
                                    }
                                }
                            }

                            // The ipV6 version works exactly the same, just with larger storage for the
                            // larger addresses. Look at the ipv4 version notes for clarification on anything.
                            if (parseResult.IPv6Header != null && parseResult.TcpHeader != null)
                            {
                                if (parseResult.TcpHeader->SrcPort == m_v6HttpProxyPort || parseResult.TcpHeader->SrcPort == m_v6HttpsProxyPort)
                                {
                                    modifiedPacket = true;

                                    parseResult.TcpHeader->SrcPort = Volatile.Read(ref m_v6ReturnPorts[parseResult.TcpHeader->DstPort]);
                                    addr.Outbound = false;

                                    var dstIp = parseResult.IPv6Header->DstAddr;
                                    parseResult.IPv6Header->DstAddr = parseResult.IPv6Header->SrcAddr;
                                    parseResult.IPv6Header->SrcAddr = dstIp;
                                }
                                else
                                {
                                    if (Volatile.Read(ref m_v6ShouldFilter[parseResult.TcpHeader->SrcPort]) == (int)FirewallAction.FilterApplication)
                                    {
                                        modifiedPacket = true;

                                        // If the process was identified as a process that is permitted
                                        // to access the internet, and is not a system process or
                                        // ourselves, then we divert its packets back inbound to the
                                        // local machine, changing the destination port appropriately.
                                        var dstAddress = parseResult.IPv6Header->DstAddr;

                                        parseResult.IPv6Header->DstAddr = parseResult.IPv6Header->SrcAddr;
                                        parseResult.IPv6Header->SrcAddr = dstAddress;
                                        addr.Outbound = false;

                                        Volatile.Write(ref m_v6ReturnPorts[parseResult.TcpHeader->SrcPort], parseResult.TcpHeader->DstPort);

                                        GoproxyWrapper.GoProxy.Instance.SetDestPortForLocalPort(parseResult.TcpHeader->SrcPort, parseResult.TcpHeader->DstPort);
                                        // Unless we know for sure this is an encrypted connection via
                                        // the HTTP port, we should always default to sending to the
                                        // non-encrypted listener.
                                        var encrypted = Volatile.Read(ref m_v6EncryptionHints[parseResult.TcpHeader->SrcPort]);

                                        parseResult.TcpHeader->DstPort = encrypted ? m_v6HttpsProxyPort : m_v6HttpProxyPort;
                                    }
                                }
                            }
                        } // if(!isLocalIpv4)
                    }// if (addr.Direction == WINDIVERT_DIRECTION_OUTBOUND)

                    if (!dropPacket)
                    {
                        if (modifiedPacket)
                        {
                            var sumsCalculated = WinDivert.WinDivertHelperCalcChecksums(packet, recvLength, ref addr, WinDivertChecksumHelperParam.All);

                            if (sumsCalculated <= 0)
                            {
                                m_logger.Warn("Modified packet reported that no checksums were calculated");
                            }
                        }

                        WinDivert.WinDivertSendEx(m_diversionHandle, packet, recvLength, 0, ref addr);
                    }
                    else
                    {
                        Console.WriteLine("dropping a packet");
                    }
                }
                catch (Exception loopException)
                {
                    m_logger.Error(loopException);
                }
            } // while (m_running)
        }

        /// <summary>
        /// If running, stops the diversion process and disposes of diversion handles.
        /// </summary>
        public void Stop()
        {
            lock (m_startStopLock)
            {
                if (!m_running)
                {
                    return;
                }

                m_running = false;

                foreach (var dt in m_diversionThreads)
                {
                    dt.Join();
                }

                WinDivert.WinDivertClose(m_diversionHandle);
            }
        }

        public static bool IsInternalIp(IPAddress toTest)
        {
            if(toTest.IsIPv6LinkLocal || toTest.IsIPv6SiteLocal || toTest.IsPrivateIpv4Address() || IPAddress.IsLoopback(toTest))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Handles the process of inspecting a new TCP connection, seeking the user's decision on
        /// what to do with the connection, and then applying that decision in code in such a way as
        /// to cause the packet filtering loop to apply the user's decision.
        /// </summary>
        /// <param name="connInfo">
        /// The state of the appropriate TCP table at the time of the new connectio.
        /// </param>
        /// <param name="tcpHeader">
        /// The TCP header from the first packet in the new connection/flow.
        /// </param>
        /// <param name="isIpv6">
        /// Whether or not this is from an IPV6 connection.
        /// </param>
        private unsafe void HandleNewTcpConnection(ITcpConnectionInfo connInfo, TcpHeader* tcpHeader, bool isIpv6)
        {
            if (connInfo != null && connInfo.OwnerPid == m_thisPid)
            {
                // This is our process.
                switch (isIpv6)
                {
                    case true:
                        {
                            Volatile.Write(ref m_v6ShouldFilter[tcpHeader->SrcPort], (int)FirewallAction.DontFilterApplication);
                        }
                        break;

                    case false:
                        {
                            Volatile.Write(ref m_v4ShouldFilter[tcpHeader->SrcPort], (int)FirewallAction.DontFilterApplication);
                        }
                        break;
                }
            }
            else
            {                
                FirewallResponse response = null;
                if (connInfo == null || connInfo.OwnerPid == 4 || connInfo.OwnerPid == 0)
                {
                    var firewallRequest = new FirewallRequest("SYSTEM", tcpHeader->SrcPort, tcpHeader->DstPort, connInfo == null ? 0L : connInfo.OwnerPid);
                    response = ConfirmDenyFirewallAccess?.Invoke(firewallRequest);
                }
                else
                {

                    if (IsInternalIp(connInfo.RemoteAddress))
                    {
                        response = new FirewallResponse(FirewallAction.DontFilterApplication);
                    }
                    else
                    {
                        // No need to null check here, because the above IF catches whenever connInfo
                        // is null.
                        var procPath = connInfo.OwnerProcessPath.Length > 0 ? connInfo.OwnerProcessPath : "SYSTEM";
                        var firewallRequest = new FirewallRequest(procPath, tcpHeader->SrcPort, tcpHeader->DstPort, connInfo.OwnerPid);
                        response = ConfirmDenyFirewallAccess?.Invoke(firewallRequest);
                    }
                }


                if (response == null)
                {
                    // The user couldn't be bothered to give us an answer, so just go ahead and
                    // let the packet through.

                    switch (isIpv6)
                    {
                        case true:
                            {
                                Volatile.Write(ref m_v6ShouldFilter[tcpHeader->SrcPort], (byte)FirewallAction.DontFilterApplication);

                                Volatile.Write(ref m_v6EncryptionHints[tcpHeader->SrcPort], (tcpHeader->DstPort == m_httpsStandardPort || tcpHeader->DstPort == m_httpsAltPort));
                            }
                            break;

                        case false:
                            {
                                Volatile.Write(ref m_v4ShouldFilter[tcpHeader->SrcPort], (byte)FirewallAction.DontFilterApplication);

                                Volatile.Write(ref m_v4EncryptionHints[tcpHeader->SrcPort], (tcpHeader->DstPort == m_httpsStandardPort || tcpHeader->DstPort == m_httpsAltPort));
                            }
                            break;
                    }
                }
                else
                {
                    switch (isIpv6)
                    {
                        case true:
                            {
                                Volatile.Write(ref m_v6ShouldFilter[tcpHeader->SrcPort], (byte)response.Action);

                                Volatile.Write(ref m_v6EncryptionHints[tcpHeader->SrcPort], response.EncryptedHint ?? (tcpHeader->DstPort == m_httpsStandardPort || tcpHeader->DstPort == m_httpsAltPort));
                            }
                            break;

                        case false:
                            {
                                Volatile.Write(ref m_v4ShouldFilter[tcpHeader->SrcPort], (byte)response.Action);

                                Volatile.Write(ref m_v4EncryptionHints[tcpHeader->SrcPort], response.EncryptedHint ?? (tcpHeader->DstPort == m_httpsStandardPort || tcpHeader->DstPort == m_httpsAltPort));
                            }
                            break;
                    }
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="localPort">This port MUST BE network byte order. Performance optimizations mumble-mumble.</param>
        /// <param name="localAddress"></param>
        /// <returns></returns>
        private ITcpConnectionInfo GetLocalPacketInfo(ushort localPort, IPAddress localAddress)
        {
            switch (localAddress.AddressFamily)
            {
                case System.Net.Sockets.AddressFamily.InterNetwork:
                    {
                        return NetworkTables.GetTcp4Table().Where(x => x.LocalPort == localPort && (x.LocalAddress.Equals(localAddress) || x.LocalAddress.Equals(IPAddress.Any)))
                            .FirstOrDefault();
                    }

                case System.Net.Sockets.AddressFamily.InterNetworkV6:
                    {
                        return NetworkTables.GetTcp6Table().Where(x => x.LocalPort == localPort && (x.LocalAddress.Equals(localAddress) || x.LocalAddress.Equals(IPAddress.IPv6Any))).FirstOrDefault();
                    }
            }

            return null;
        }
    }
}