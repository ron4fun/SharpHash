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
    }
}