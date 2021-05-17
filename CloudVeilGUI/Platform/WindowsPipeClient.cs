/*
* Copyright © 2017-2018 Cloudveil Technology Inc.
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

﻿using Citadel.IPC.Messages;
using Filter.Platform.Common.IPC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Gui.CloudVeil.Platform
{
    public class WindowsPipeClient : IPipeClient
    {
        private NamedPipeWrapper.NamedPipeClient<BaseMessage> client;

        public WindowsPipeClient(string channel, bool autoReconnect = false)
        {
            client = new NamedPipeWrapper.NamedPipeClient<BaseMessage>(channel);

            client.Connected += (conn) => Connected?.Invoke();
            client.Disconnected += (conn) => Disconnected?.Invoke();
            client.ServerMessage += (conn, msg) => ServerMessage?.Invoke(msg);
            client.Error += (ex) => Error?.Invoke(ex);
        }

        public bool AutoReconnect
        {
            get
            {
                return client.AutoReconnect;
            }

            set
            {
                client.AutoReconnect = value;
            }
        }

        public event ClientConnectionHandler Connected;
        public event ClientConnectionHandler Disconnected;
        public event ServerMessageHandler ServerMessage;
        public event PipeExceptionHandler Error;

        public void PushMessage(BaseMessage msg) => client.PushMessage(msg);
        public void Start() => client.Start();
        public void Stop() => client.Stop();
        public void WaitForConnection() => client.WaitForConnection();
    }
}
