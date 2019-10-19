using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class SHA2_512_256Tests
    {
        protected IHash hash = HashFactory.Crypto.CreateSHA2_512_256();

        protected string ExpectedHashOfEmptyData = "C672B8D1EF56ED28AB87C3622C5114069BDD3AD7B8F9737498D0C01ECEF0967A";
        protected string ExpectedHashOfDefaultData = "E1792BAAAEBFC58E213D0BA628BF2FF22CBA10526075702F7C1727B76BEB107B";
        protected string ExpectedHashOfOnetoNine = "1877345237853A31AD79E14C1FCB0DDCD3DF9973B61AF7F906E4B4D052CC9416";
        protected string ExpectedHashOfabcde = "DE8322B46E78B67D4431997070703E9764E03A1237B896FD8B379ED4576E8363";
        protected string ExpectedHashOfDefaultDataWithHMACWithLongKey = "5EF407B913662BE3D98F5DA20D55C2A45D3F3E4FF771B2C2A482E35F6A757E71";
        protected string ExpectedHashOfDefaultDataWithHMACWithShortKey = "1467239C9D47E1962905D03D7006170A04D05E4508BB47E30AD9481FBDA975FF";

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
