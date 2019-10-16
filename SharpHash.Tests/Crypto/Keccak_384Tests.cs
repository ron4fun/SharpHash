using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Keccak_384Tests
    {
        protected IHash hash = new Keccak_384();

        protected string ExpectedHashOfEmptyData = "2C23146A63A29ACF99E73B88F8C24EAA7DC60AA771780CCC006AFBFA8FE2479B2DD2B21362337441AC12B515911957FF";
        protected string ExpectedHashOfDefaultData = "6A53977DFA0BCDCF069635CF541AB64C7E41923FCB3A5B049AB98878411D0E71DF95FCAB0072F1AE8B931BF4490B823E";
        protected string ExpectedHashOfOnetoNine = "EFCCAE72CE14656C434751CF737E70A57AB8DD2C76F5ABE01E52770AFFD77B66D2B80977724A00A6D971B702906F8032";
        protected string ExpectedHashOfabcde = "6E577A02A783232ACF34841399883F5F69D9AC78F48C7F4431CBC4F669C2A0F1CA3B1BECB7701B8315588D64D6C3746A";
        protected string ExpectedHashOfDefaultDataWithHMACWithLongKey = "A7740E29EEF80306DA09D7AF0868E925D6144996F99A01F973F03C4BD85D1EC20567936CA34A443B62A890AD8D263D2A";
        protected string ExpectedHashOfDefaultDataWithHMACWithShortKey = "044628643016E3EA30DE6CA3A8A1276F6BF1A5443CEF96BAA73199CF64FFC52D7F38254C671DB2933FFC8DD3E5B77223";

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

        public void TestHMACWithDefaultDataAndLongKey()
        {
            IHMAC hmac = new HMACNotBuildInAdapter(hash);
            hmac.Key = Converters.ConvertStringToBytes(TestConstants.HMACLongStringKey);
            string ActualString = hmac.ComputeString(TestConstants.DefaultData).ToString();

            Assert.AreEqual(ExpectedHashOfDefaultDataWithHMACWithLongKey, ActualString);
        }

        public void TestHMACWithDefaultDataAndShortKey()
        {
            IHMAC hmac = new HMACNotBuildInAdapter(hash);
            hmac.Key = Converters.ConvertStringToBytes(TestConstants.HMACShortStringKey);
            string ActualString = hmac.ComputeString(TestConstants.DefaultData).ToString();

            Assert.AreEqual(ExpectedHashOfDefaultDataWithHMACWithShortKey, ActualString);
        }

        public void TestHMACCloneIsCorrect()
        {
            TestHelper.TestHMACCloneIsCorrect(hash);
        }

    }

}
