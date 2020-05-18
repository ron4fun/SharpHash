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
    public abstract class ShakeBaseTests : HashAdapter1BaseTests
    {
        protected string ExpectedVeryLongShakeOfEmptyString { get; set; }

        protected IXOF VeryLongShake { get; set; }

        [TestMethod]
        public void TestVeryLongShakeOfEmptyString()
        {
            string ActualString = VeryLongShake.ComputeString(
                TestConstants.EmptyData, Encoding.UTF8).ToString();

            string ExpectedString = ExpectedVeryLongShakeOfEmptyString;

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.",
                ExpectedString, ActualString));
        }

        [TestMethod]
        public void TestVeryLongShakeOfEmptyStringWithStreamingOutput()
        {
            byte[] TempResult, ExpectedChunk, ActualChunk;

            byte[] Expected = Converters.ConvertHexStringToBytes(ExpectedVeryLongShakeOfEmptyString);

            TempResult = new byte[1000];
            VeryLongShake.Initialize();
            VeryLongShake.TransformString(TestConstants.EmptyData, Encoding.UTF8);

            VeryLongShake.DoOutput(ref TempResult, 0, 250);

            ActualChunk = new byte[250];
            Utils.Utils.Memcopy(ref ActualChunk, TempResult, 250, 0);

            ExpectedChunk = new byte[250];
            Utils.Utils.Memcopy(ref ExpectedChunk, Expected, 250, 0);

            Assert.IsTrue(TestHelper.Compare(ExpectedChunk, ActualChunk),
                $"{VeryLongShake.Name} Streaming Test 1 Mismatch");

            VeryLongShake.DoOutput(ref TempResult, 250, 250);

            Utils.Utils.Memcopy(ref ActualChunk, TempResult, 250, 250);
            Utils.Utils.Memcopy(ref ExpectedChunk, Expected, 250, 250);

            Assert.IsTrue(TestHelper.Compare(ExpectedChunk, ActualChunk),
                 $"{VeryLongShake.Name} Streaming Test 2 Mismatch");

            VeryLongShake.DoOutput(ref TempResult, 500, 250);

            Utils.Utils.Memcopy(ref ActualChunk, TempResult, 250, 500);
            Utils.Utils.Memcopy(ref ExpectedChunk, Expected, 250, 500);

            Assert.IsTrue(TestHelper.Compare(ExpectedChunk, ActualChunk),
                 $"{VeryLongShake.Name} Streaming Test 3 Mismatch");

            VeryLongShake.DoOutput(ref TempResult, 750, 250);

            Utils.Utils.Memcopy(ref ActualChunk, TempResult, 250, 750);
            Utils.Utils.Memcopy(ref ExpectedChunk, Expected, 250, 750);

            Assert.IsTrue(TestHelper.Compare(ExpectedChunk, ActualChunk),
                 $"{VeryLongShake.Name} Streaming Test 4 Mismatch");

            string ActualString = Converters.ConvertBytesToHexString(TempResult, false);
            string ExpectedString = ExpectedVeryLongShakeOfEmptyString;

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.",
                ExpectedString, ActualString));

            // Verify that Initialization Works
            VeryLongShake.Initialize();

            VeryLongShake.DoOutput(ref TempResult, 0, 250);

            Utils.Utils.Memcopy(ref ActualChunk, TempResult, 250, 0);
            Utils.Utils.Memcopy(ref ExpectedChunk, Expected, 250, 0);

            Assert.IsTrue(TestHelper.Compare(ExpectedChunk, ActualChunk),
                $"{VeryLongShake.Name} Streaming Initialization Test Fail");
        }
    }
}