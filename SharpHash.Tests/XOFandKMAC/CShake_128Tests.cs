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
    public class CShake_128Tests : CShakeTests
    {
        protected IHash hash;

        protected string ExpectedHashOfZeroToThreeInHex = "C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5";
        protected string ExpectedHashOfZeroToOneHundredAndNinetyNineInHex = "C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B";

        public CShake_128Tests()
        {
            hash = HashFactory.XOF.CreateCShake_128(null, FS, 256);
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
        public void TestCShake_128_Vectors()
        {
            TestHelper.TestActualAndExpectedData(
                Converters.ConvertHexStringToBytes(TestConstants.ZeroToThreeInHex),
                ExpectedHashOfZeroToThreeInHex, hash);

            TestHelper.TestActualAndExpectedData(
                Converters.ConvertHexStringToBytes(TestConstants.ZeroToOneHundredAndNinetyNineInHex),
                ExpectedHashOfZeroToOneHundredAndNinetyNineInHex, hash);
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

        [TestMethod]
        public void TestHMACCloneIsCorrect()
        {
            TestHelper.TestHMACCloneIsCorrect(hash);
        }
    }
}