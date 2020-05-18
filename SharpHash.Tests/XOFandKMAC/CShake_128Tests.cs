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
    public class CShake_128Tests : CShakeBaseTests
    {
        public CShake_128Tests()
        {
            hash = HashFactory.XOF.CreateCShake_128(null, FS, 256);
            ExpectedHashOfZeroToThreeInHex = "C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5";
            ExpectedHashOfZeroToOneHundredAndNinetyNineInHex = "C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B";
        } //

        [TestMethod]
        public void TestCShakeAndShakeAreSameWhenNAndSAreEmpty()
        {
            IHash Shake_128, CShake_128;
            byte[] Data;

            Shake_128 = HashFactory.XOF.CreateShake_128(8000);
            CShake_128 = HashFactory.XOF.CreateCShake_128(null, null, 8000);

            string ExpectedString = Shake_128.ComputeString(TestConstants.EmptyData, Encoding.UTF8)
                .ToString();

            string ActualString = CShake_128.ComputeString(TestConstants.EmptyData, Encoding.UTF8)
                .ToString();

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.",
                ExpectedString, ActualString));

            Data = Converters.ConvertHexStringToBytes(TestConstants.FEEAABEEF);
            Shake_128 = HashFactory.XOF.CreateShake_128(8000);
            CShake_128 = HashFactory.XOF.CreateCShake_128(null, null, 8000);

            ExpectedString = Shake_128.ComputeBytes(Data).ToString();
            ActualString = CShake_128.ComputeBytes(Data).ToString();

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