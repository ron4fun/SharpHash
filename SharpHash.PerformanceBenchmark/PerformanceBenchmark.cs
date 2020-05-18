///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019 - 2020  Mbadiwe Nnaemeka Ronald
/// Github Repository <https://github.com/ron4fun/SharpHash>
///
/// The contents of this file are subject to the
/// Mozilla Public License Version 2.0 (the "License");
/// you may not use this file except in
/// compliance with the License. You may obtain a copy of the License
/// at https://www.mozilla.org/en-US/MPL/2.0/
///
/// Software distributed under the License is distributed on an "AS IS"
/// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
/// the License for the specific language governing rights and
/// limitations under the License.
///
/// Acknowledgements:
///
/// Thanks to Ugochukwu Mmaduekwe (https://github.com/Xor-el) for his creative
/// development of this library in Pascal/Delphi (https://github.com/Xor-el/HashLib4Pascal).
///
/// Also, I will like to thank Udezue Chukwunwike (https://github.com/IzarchTech) for
/// his contributions to the growth and development of this library.
///
////////////////////////////////////////////////////////////////////////

using SharpHash.Base;
using SharpHash.Interfaces;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace SharpHash.PerformanceBenchmark
{
    public sealed class PerformanceBenchmark
    {
        private static Random Random { get; }

        static PerformanceBenchmark()
        {
            Random = new Random();
        }

        public static string Calculate(IHash hashInstance, string namePrefix = "", Int32 size = 65536)
        {
            const UInt32 THREE_SECONDS_IN_MILLISECONDS = 3000;
            string newName = "";
            var data = new byte[size];

            for (int i = 0; i < size; i++)
                data[i] = (byte)Random.Next(size);

            var maxRate = 0.0;
            var totalMilliSeconds = 0.0;
            for (int i = 0; i < 3; i++)
            {
                Int64 total = 0;

                while (totalMilliSeconds < THREE_SECONDS_IN_MILLISECONDS)
                {
                    Stopwatch stopWatch = Stopwatch.StartNew();

                    hashInstance.ComputeBytes(data);
                    total = total + data.Length;

                    stopWatch.Stop();

                    // Get the elapsed time as a TimeSpan value.
                    TimeSpan ts = stopWatch.Elapsed;

                    totalMilliSeconds = totalMilliSeconds + ts.TotalMilliseconds;
                }

                maxRate = Math.Max(total / (totalMilliSeconds / 1000) / 1024 / 1024, maxRate);
            }

            if (!string.IsNullOrWhiteSpace(namePrefix))
                newName = string.Format($"{hashInstance.Name} {namePrefix}");
            else
                newName = hashInstance.Name;

            return string.Format("{0} Throughput: {1:0.00} MB/s with Blocks of {2} KB", newName, maxRate, size / 1024);
        }

        public static void DoBenchmark(ref List<string> stringList)
        {
            if (stringList == null)
                throw new Exception("StringList Instance cannot be null");

            stringList.Clear();

            //stringList.Add(Calculate(HashFactory.Checksum.CreateAdler32()));

            //stringList.Add(Calculate(HashFactory.Checksum.CreateCRC(CRCStandard.CRC32), "PKZIP_Generic"));

            //stringList.Add(Calculate(HashFactory.Checksum.CreateCRC32_PKZIP(), "Fast"));

            //stringList.Add(Calculate(HashFactory.Hash32.CreateMurmurHash3_x86_32()));

            //stringList.Add(Calculate(HashFactory.Hash32.CreateXXHash32()));

            //stringList.Add(Calculate(HashFactory.Hash64.CreateSipHash2_4()));

            //stringList.Add(Calculate(HashFactory.Hash64.CreateXXHash64()));

            //stringList.Add(Calculate(HashFactory.Hash128.CreateMurmurHash3_x86_128()));

            //stringList.Add(Calculate(HashFactory.Hash128.CreateMurmurHash3_x64_128()));

            stringList.Add(Calculate(HashFactory.Crypto.CreateMD5()));

            //stringList.Add(Calculate(HashFactory.Crypto.CreateSHA1()));

            //stringList.Add(Calculate(HashFactory.Crypto.CreateSHA2_256()));

            //stringList.Add(Calculate(HashFactory.Crypto.CreateSHA2_512()));

            //stringList.Add(Calculate(HashFactory.Crypto.CreateSHA3_256()));

            //stringList.Add(Calculate(HashFactory.Crypto.CreateSHA3_512()));

            //stringList.Add(Calculate(HashFactory.Crypto.CreateBlake2B_256()));

            //stringList.Add(Calculate(HashFactory.Crypto.CreateBlake2B_512()));

            //stringList.Add(Calculate(HashFactory.Crypto.CreateBlake2S_128()));

            //stringList.Add(Calculate(HashFactory.Crypto.CreateBlake2S_256()));
        }
    }
}