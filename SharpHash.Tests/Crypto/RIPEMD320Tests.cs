using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class RIPEMD320Tests
    {
        protected IHash hash = HashFactory.Crypto.CreateRIPEMD320();

        protected string ExpectedHashOfEmptyData = "22D65D5661536CDC75C1FDF5C6DE7B41B9F27325EBC61E8557177D705A0EC880151C3A32A00899B8";
        protected string ExpectedHashOfDefaultData = "004A1899CCA02BFD4055129304D55F364E35F033BB74B784AFC93F7268291D8AF84F2C64C5CCACD0";
        protected string ExpectedHashOfOnetoNine = "7E36771775A8D279475D4FD76B0C8E412B6AD085A0002475A148923CCFA5D71492E12FA88EEAF1A9";
        protected string ExpectedHashOfabcde = "A94DC1BC825DB64E97718305CE36BFEF32CC5410A630999678BCD89CC38C424269012EC8C5A95830";
        protected string ExpectedHashOfDefaultDataWithHMACWithLongKey = "248D14ED08F0F49D175F4DC487A64B81F06D78077D1CF975BBE5D47627995990EBE45E6B7EDF9362";
        protected string ExpectedHashOfDefaultDataWithHMACWithShortKey = "4D3DFCCB43E5A60611A850C2141086CB16752505BA12E1B7953EA8859CB1E1DF3A698562A46DB41C";

        [TestMethod]
        public void TestEmptyString()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.EmptyData,
                ExpectedHashOfEmptyData, hash);
        }

        [TestMethod]
        public void TestDefaultData()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.DefaultData,
                ExpectedHashOfDefaultData, hash);
        }

        [TestMethod]
        public void TestOnetoNine()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.OnetoNine,
                ExpectedHashOfOnetoNine, hash);
        }

        [TestMethod]
        public void TestBytesabcde()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.Bytesabcde,
                ExpectedHashOfabcde, hash);
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
        public void TestHMACWithDefaultDataAndLongKey()
        {
            IHMAC hmac = HashFactory.HMAC.CreateHMAC(hash);
            hmac.Key = Converters.ConvertStringToBytes(TestConstants.HMACLongStringKey);
            string ActualString = hmac.ComputeString(TestConstants.DefaultData).ToString();

            Assert.AreEqual(ExpectedHashOfDefaultDataWithHMACWithLongKey, ActualString);
        }

        [TestMethod]
        public void TestHMACWithDefaultDataAndShortKey()
        {
            IHMAC hmac = HashFactory.HMAC.CreateHMAC(hash);
            hmac.Key = Converters.ConvertStringToBytes(TestConstants.HMACShortStringKey);
            string ActualString = hmac.ComputeString(TestConstants.DefaultData).ToString();

            Assert.AreEqual(ExpectedHashOfDefaultDataWithHMACWithShortKey, ActualString);
        }

        [TestMethod]
        public void TestHMACCloneIsCorrect()
        {
            TestHelper.TestHMACCloneIsCorrect(hash);
        }

    }

}
