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
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System;
using System.Text;

namespace SharpHash
{
    [TestClass]
    public abstract class HashBaseTests : XOFBaseTests
    {
        protected IHash hash { get; set; }

        protected string ExpectedHashOfEmptyData { get; set; }
        protected string ExpectedHashOfDefaultData { get; set; }

        [TestMethod]
        public void TestEmptyString()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.EmptyData,
                ExpectedHashOfEmptyData, hash);
        }

        [TestMethod]
        public void TestForNullBytes()
        {
            TestHelper.TestForNullBytes(hash);
        }

        [TestMethod]
        public void TestDefaultData()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.DefaultData,
            ExpectedHashOfDefaultData, hash);
        }

        [TestMethod]
        public void TestEmptyStream()
        {
            TestHelper.TestEmptyStream(ExpectedHashOfEmptyData, hash);
        }

        [TestMethod]
        public void TestIncrementalHash()
        {
            TestHelper.TestIncrementalHash(TestConstants.DefaultData,
            ExpectedHashOfDefaultData, hash);
        }

        [TestMethod]
        public void TestIndexChunkedDataIncrementalHash()
        {
            Int32 Count, i;
            byte[] temp, ChunkedDataBytes;
            string ActualString, ExpectedString;

            ChunkedDataBytes = Converters.ConvertStringToBytes(TestConstants.ChunkedData,
                Encoding.UTF8);
            for (i = 0; i < ChunkedDataBytes.Length; i++)
            {
                Count = ChunkedDataBytes.Length - i;

                temp = new byte[Count];
                Utils.Utils.Memcopy(ref temp, ChunkedDataBytes, Count, i);

                hash.Initialize();

                hash.TransformBytes(ChunkedDataBytes, i, Count);

                ActualString = hash.TransformFinal().ToString();
                ExpectedString = hash.ComputeBytes(temp).ToString();

                Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.",
                ExpectedString, ActualString));
            }
        }

        [TestMethod]
        public void TestHashCloneIsCorrect()
        {
            TestHelper.TestHashCloneIsCorrect(hash);
        }

        [TestMethod]
        public void TestHashCloneIsUnique()
        {
            TestHelper.TestHashCloneIsUnique(hash);
        }
    }
}