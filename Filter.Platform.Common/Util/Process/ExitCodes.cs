﻿/*
* Copyright © 2017-2018 Cloudveil Technology Inc.
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

namespace Filter.Platform.Common.Util
{
    /// <summary>
    /// Various exit codes indicating the reason for a shutdown. 
    /// </summary>
    public enum ExitCodes : int
    { 
        ShutdownCriticalError = -1,
        ShutdownWithSafeguards = 100,
        ShutdownWithoutSafeguards = 101,
        ShutdownForUpdate = 102,
        ShutdownProcessAlreadyOpen = 201,
        ShutdownInitializationError = 202,
    }
}