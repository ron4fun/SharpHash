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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHash.Checksum.Tests
{
    public static class EnumUtil
    {
        public static IEnumerable<T> GetValues<T>() => Enum.GetValues(typeof(T)).Cast<T>();
        
    } // end class EnumUtil

    [TestClass]
    public class CRCTests
    {
        protected IHash crcObj = null;
        protected IEnumerable<CRCStandard> CRCStandardValues = EnumUtil.GetValues<CRCStandard>();

        [TestMethod]
        public void TestAnotherChunkedDataIncrementalHash()
        {
            string temp, ActualString, ExpectedString;
            Int32 x, size, i;

            for (x = 0; x < TestConstants.chunkSize.Length / sizeof(Int32); x++)
            {
                size = TestConstants.chunkSize[x];

                foreach (CRCStandard Idx in CRCStandardValues)
                {
                    crcObj = HashFactory.Checksum.CreateCRC(Idx);
                    crcObj.Initialize();

                    i = size;
                    while (i < TestConstants.ChunkedData.Length)
                    {
                        temp = TestConstants.ChunkedData.Substring(i - size, size);
                        crcObj.TransformString(temp, Encoding.UTF8);

                        i += size;
                    } // end while

                    temp = TestConstants.ChunkedData.Substring((i - size));
                    crcObj.TransformString(temp, Encoding.UTF8);

                    ActualString = crcObj.TransformFinal().ToString();

                    ExpectedString = HashFactory.Checksum.CreateCRC(Idx)
                        .ComputeString(TestConstants.ChunkedData, Encoding.UTF8).ToString();

                    Assert.AreEqual(ExpectedString, ActualString);
                } // end for
            } // end for
        }

        [TestMethod]
        public void TestCheckValue()
        {
            string ActualString, ExpectedString;

            foreach (CRCStandard Idx in CRCStandardValues)
            {
                crcObj = HashFactory.Checksum.CreateCRC(Idx);

                ExpectedString = ((crcObj as ICRC).CheckValue.ToString("X"));

                ActualString = TestHelper.LeftStrip(crcObj.ComputeString(TestConstants.OnetoNine, Encoding.UTF8).ToString(), '0');

                Assert.AreEqual(ExpectedString, ActualString);
            } // end foreach
        }

        [TestMethod]
        public void TestForNullBytes()
        {
            foreach (CRCStandard Idx in CRCStandardValues)
            {
                crcObj = HashFactory.Checksum.CreateCRC(Idx);
                TestHelper.TestForNullBytes(crcObj);
            } // end foreach
        }

        [TestMethod]
        public void TestCheckValueWithIncrementalHash()
        {
            string ExpectedString;

            foreach (CRCStandard Idx in CRCStandardValues)
            {
                crcObj = HashFactory.Checksum.CreateCRC(Idx);

                ExpectedString = ((crcObj as ICRC).CheckValue.ToString("X"));

                TestHelper.TestIncrementalHash(TestConstants.OnetoNine,
                ExpectedString, crcObj);
            }
        }

        [TestMethod]
        public void TestHashCloneIsCorrect()
        {
            IHash Original, Copy;
            byte[] MainData, ChunkOne, ChunkTwo;
            Int32 Count;
            string ActualString, ExpectedString;

            MainData = Converters.ConvertStringToBytes(TestConstants.DefaultData, Encoding.UTF8);
            Count = MainData.Length - 3;

            ChunkOne = new byte[Count];
            ChunkTwo = new byte[MainData.Length - Count];

            Utils.Utils.Memcopy(ref ChunkOne, MainData, Count);
            Utils.Utils.Memcopy(ref ChunkTwo, MainData, MainData.Length - Count, Count);

            foreach (CRCStandard Idx in CRCStandardValues)
            {
                Original = HashFactory.Checksum.CreateCRC(Idx);
                Original.Initialize();

                Original.TransformBytes(ChunkOne);
                // Make Copy Of Current State
                Copy = Original.Clone();
                Original.TransformBytes(ChunkTwo);
                ExpectedString = Original.TransformFinal().ToString();

                Copy.TransformBytes(ChunkTwo);
                ActualString = Copy.TransformFinal().ToString();

                Assert.AreEqual(ActualString, ExpectedString);
            } // end foreach
        }

        [TestMethod]
        public void TestHashCloneIsUnique()
        {
            IHash Original, Copy;

            foreach (CRCStandard Idx in CRCStandardValues)
            {
                Original = HashFactory.Checksum.CreateCRC(Idx);
                Original.Initialize();
                Original.BufferSize = (64 * 1024); // 64Kb
                                                   // Make Copy Of Current State
                Copy = Original.Clone();
                Copy.BufferSize = (128 * 1024); // 128Kb

                Assert.AreNotEqual(Original.BufferSize, Copy.BufferSize);
            } // end foreach
        }
    } // end class CRCTests

    [TestClass]
    public class CRC32FastTests
    {
        protected IHash crcObj = null;

        protected readonly UInt32 CRC32_PKZIP_Check_Value = 0xCBF43926;
        protected readonly UInt32 CRC32_CASTAGNOLI_Check_Value = 0xE3069283;
        protected readonly Int32[] WorkingIndex = new Int32[] { 0, 1 };

        protected UInt32 GetWorkingValue(Int32 a_index)
        {
            switch (a_index)
            {
                case 0:
                    crcObj = HashFactory.Checksum.CreateCRC32_PKZIP();
                    return CRC32_PKZIP_Check_Value;

                case 1:
                    crcObj = HashFactory.Checksum.CreateCRC32_CASTAGNOLI();
                    return CRC32_CASTAGNOLI_Check_Value;
            } // end switch

            throw new Exception($"Invalid Index, \"{a_index }\"");
        } // end function GetWorkingValue

        [TestMethod]
        public void TestAnotherChunkedDataIncrementalHash()
        {
            string temp, ActualString, ExpectedString;
            Int32 x, size, i;

            for (x = 0; x < TestConstants.chunkSize.Length / sizeof(Int32); x++)
            {
                size = TestConstants.chunkSize[x];

                foreach (var Idx in WorkingIndex)
                {
                    GetWorkingValue(Idx);
                    crcObj.Initialize();

                    i = size;
                    while (i < TestConstants.ChunkedData.Length)
                    {
                        temp = TestConstants.ChunkedData.Substring(i - size, size);
                        crcObj.TransformString(temp, Encoding.UTF8);

                        i += size;
                    } // end while

                    temp = TestConstants.ChunkedData.Substring((i - size));
                    crcObj.TransformString(temp, Encoding.UTF8);

                    ActualString = crcObj.TransformFinal().ToString();

                    ExpectedString = crcObj.ComputeString(TestConstants.ChunkedData, Encoding.UTF8)
                        .ToString();

                    Assert.AreEqual(ExpectedString, ActualString);
                } // end for
            } // end for
        }

        [TestMethod]
        public void TestCheckValue()
        {
            string ActualString, ExpectedString;
            UInt32 Check_Value;

            foreach (var Idx in WorkingIndex)
            {
                Check_Value = GetWorkingValue(Idx);

                ExpectedString = Check_Value.ToString("X");

                ActualString = TestHelper.LeftStrip(crcObj.ComputeString(TestConstants.OnetoNine, Encoding.UTF8).ToString(), '0');

                Assert.AreEqual(ExpectedString, ActualString);
            } // end foreach
        }

        [TestMethod]
        public void TestForNullBytes()
        {
            foreach (var Idx in WorkingIndex)
            {
                GetWorkingValue(Idx);
                TestHelper.TestForNullBytes(crcObj);
            } // end foreach
        }

        [TestMethod]
        public void TestCheckValueWithIncrementalHash()
        {
            string ExpectedString;
            UInt32 Check_Value;

            foreach (var Idx in WorkingIndex)
            {
                Check_Value = GetWorkingValue(Idx);
                crcObj.Initialize();

                ExpectedString = Check_Value.ToString("X");

                TestHelper.TestIncrementalHash(TestConstants.OnetoNine,
                ExpectedString, crcObj);
            }
        }

        [TestMethod]
        public void TestHashCloneIsCorrect()
        {
            IHash Original, Copy;
            byte[] MainData, ChunkOne, ChunkTwo;
            Int32 Count;
            string ActualString, ExpectedString;

            MainData = Converters.ConvertStringToBytes(TestConstants.DefaultData, Encoding.UTF8);
            Count = MainData.Length - 3;

            ChunkOne = new byte[Count];
            ChunkTwo = new byte[MainData.Length - Count];

            Utils.Utils.Memcopy(ref ChunkOne, MainData, Count);
            Utils.Utils.Memcopy(ref ChunkTwo, MainData, MainData.Length - Count, Count);

            foreach (var Idx in WorkingIndex)
            {
                GetWorkingValue(Idx);
                Original = crcObj;
                Original.Initialize();

                Original.TransformBytes(ChunkOne);
                // Make Copy Of Current State
                Copy = Original.Clone();
                Original.TransformBytes(ChunkTwo);
                ExpectedString = Original.TransformFinal().ToString();

                Copy.TransformBytes(ChunkTwo);
                ActualString = Copy.TransformFinal().ToString();

                Assert.AreEqual(ActualString, ExpectedString);
            } // end foreach
        }

        [TestMethod]
        public void TestHashCloneIsUnique()
        {
            IHash Original, Copy;

            foreach (var Idx in WorkingIndex)
            {
                GetWorkingValue(Idx);
                Original = crcObj;
                Original.Initialize();
                Original.BufferSize = (64 * 1024); // 64Kb
                                                   // Make Copy Of Current State
                Copy = Original.Clone();
                Copy.BufferSize = (128 * 1024); // 128Kb

                Assert.AreNotEqual(Original.BufferSize, Copy.BufferSize);
            } // end foreach
        }
    } // end class CRC32FastTests
}