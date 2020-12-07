/*
* Copyright © 2017 Cloudveil Technology Inc.
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Filter.Platform.Common
{
    public interface IAuthenticationStorage
    {
        string UserEmail { get; set; }

        string AuthToken { get; set; }

        string AuthId { get; set; }

        string DeviceId { get; set; }
    }
}
