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
using System.Text;

namespace SharpHash.XOFandKMAC.Tests
{
    [TestClass]
    public class CShake_256Tests : CShakeBaseTests
    {
        public CShake_256Tests()
        {
            hash = HashFactory.XOF.CreateCShake_256(null, FS, 512);
            ExpectedHashOfZeroToThreeInHex =
            "D008828E2B80AC9D2218FFEE1D070C48" + "B8E4C87BFF32C9699D5B6896EEE0EDD1"
          + "64020E2BE0560858D9C00C037E34A969" + "37C561A74C412BB4C746469527281C8C";

            ExpectedHashOfZeroToOneHundredAndNinetyNineInHex =
            "07DC27B11E51FBAC75BC7B3C1D983E8B" + "4B85FB1DEFAF218912AC864302730917"
          + "27F42B17ED1DF63E8EC118F04B23633C" + "1DFB1574C8FB55CB45DA8E25AFB092BB";
        } //

        [TestMethod]
        public void TestCShakeAndShakeAreSameWhenNAndSAreEmpty()
        {
            IHash Shake_256, CShake_256;
            byte[] Data;

            Shake_256 = HashFactory.XOF.CreateShake_256(8000);
            CShake_256 = HashFactory.XOF.CreateCShake_256(null, null, 8000);

            string ExpectedString = Shake_256.ComputeString(TestConstants.EmptyData, Encoding.UTF8)
                .ToString();

            string ActualString = CShake_256.ComputeString(TestConstants.EmptyData, Encoding.UTF8)
                .ToString();

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.",
                ExpectedString, ActualString));

            Data = Converters.ConvertHexStringToBytes(TestConstants.FEEAABEEF);
            Shake_256 = HashFactory.XOF.CreateShake_256(8000);
            CShake_256 = HashFactory.XOF.CreateCShake_256(null, null, 8000);

            ExpectedString = Shake_256.ComputeBytes(Data).ToString();
            ActualString = CShake_256.ComputeBytes(Data).ToString();

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.",
                ExpectedString, ActualString));
        }

        [TestMethod]
        public void TestXofShouldRaiseExceptionOnWriteAfterRead()
        {
            IXOF Hash = hash as IXOF;
            Assert.ThrowsException<InvalidOperationHashLibException>(() => CallShouldRaiseException(Hash));
        }
    }
}