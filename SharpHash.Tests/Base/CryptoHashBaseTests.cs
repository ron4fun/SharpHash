using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System.Text;

namespace SharpHash
{
    [TestClass]
    public abstract class CryptoHashBaseTests : HashAdapter1BaseTests
    {
        protected static string ExpectedHashOfDefaultDataWithHMACWithLongKey { get; set; }
        protected static string ExpectedHashOfDefaultDataWithHMACWithShortKey { get; set; }

        [TestMethod]
        public void TestHMACWithDefaultDataAndLongKey()
        {
            IHMAC hmac = HashFactory.HMAC.CreateHMAC(hash);
            hmac.Key = Converters.ConvertStringToBytes(TestConstants.HMACLongStringKey,
                Encoding.UTF8);
            string ActualString = hmac.ComputeString(TestConstants.DefaultData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedHashOfDefaultDataWithHMACWithLongKey, ActualString);
        }

        [TestMethod]
        public void TestHMACWithDefaultDataAndShortKey()
        {
            IHMAC hmac = HashFactory.HMAC.CreateHMAC(hash);
            hmac.Key = Converters.ConvertStringToBytes(TestConstants.HMACShortStringKey,
                Encoding.UTF8);
            string ActualString = hmac.ComputeString(TestConstants.DefaultData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedHashOfDefaultDataWithHMACWithShortKey, ActualString);
        }

        [TestMethod]
        public void TestHMACCloneIsCorrect()
        {
            TestHelper.TestHMACCloneIsCorrect(hash);
        }
    }
}