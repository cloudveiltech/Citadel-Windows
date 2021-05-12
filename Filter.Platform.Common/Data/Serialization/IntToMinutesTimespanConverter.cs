﻿/*
* Copyright © 2017-2018 Cloudveil Technology Inc.  
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using Newtonsoft.Json;
using System;
using System.Threading;

namespace CloudVeil.Core.Data.Serialization
{
    /// <summary>
    /// This class is passed to JSON.NET for the purpose of deserializing integer values into
    /// timespans that are from minutes.
    /// </summary>
    public class IntToMinutesTimespanConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(TimeSpan);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            // To account for errors. Default to zero when NaN, etc.
            int minutes = 0;
            
            if(!int.TryParse(reader.Value.ToString(), out minutes))
            {
                minutes = 0;
            }

            if(minutes == 0)
            {
                return Timeout.InfiniteTimeSpan;
            }

            return TimeSpan.FromMinutes(minutes);
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var cast = value as TimeSpan?;
            if(cast == null)
            {
                writer.WriteValue((int?)null);
            }

            var castValue = cast.Value;

            writer.WriteValue(castValue.TotalMinutes);
        }
    }
}