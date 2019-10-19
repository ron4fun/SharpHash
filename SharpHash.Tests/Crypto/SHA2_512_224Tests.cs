using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class SHA2_512_224Tests
    {
        protected IHash hash = HashFactory.Crypto.CreateSHA2_512_224();

        protected string ExpectedHashOfEmptyData = "6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4";
        protected string ExpectedHashOfDefaultData = "7A95749FB7F4489A45275556F5D905D28E1B637DCDD6537336AB6234";
        protected string ExpectedHashOfOnetoNine = "F2A68A474BCBEA375E9FC62EAAB7B81FEFBDA64BB1C72D72E7C27314";
        protected string ExpectedHashOfabcde = "880E79BB0A1D2C9B7528D851EDB6B8342C58C831DE98123B432A4515";
        protected string ExpectedHashOfDefaultDataWithHMACWithLongKey = "B932866547894977F6E4C61D137FFC2508C639BA6786F45AC64731C8";
        protected string ExpectedHashOfDefaultDataWithHMACWithShortKey = "9BC318A84B90F7FF55C53E3F4B602EAD13BB579EB1794455B29562B4";

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
