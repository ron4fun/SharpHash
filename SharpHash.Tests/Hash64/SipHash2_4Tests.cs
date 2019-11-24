using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System;
using System.Text;

namespace SharpHash.Hash64.Tests
{
    [TestClass]
    public class SipHash2_4Tests : HashAdapter1BaseTests
    {
        private string ExpectedHashWithExternalKey { get; set; }

        public SipHash2_4Tests()
        {
            hash = HashFactory.Hash64.CreateSipHash2_4();

            ExpectedHashOfEmptyData = "310E0EDD47DB6F72";
            ExpectedHashOfDefaultData = "4ED2198628C443AA";
            ExpectedHashOfOnetoNine = "FDFE0E0296FC60CA";
            ExpectedHashOfabcde = "73B879EAE16345A7";
            ExpectedHashWithExternalKey = "4ED2198628C443AA";
        }

        [TestMethod]
        public void TestZeroToFifteenInHex()
        {
            IHashWithKey LIHashWithKey;

            string ExpectedString = ExpectedHashWithExternalKey;
            LIHashWithKey = (hash as IHashWithKey);
            LIHashWithKey.Key = Converters.ConvertHexStringToBytes(TestConstants.ZeroToFifteenInHex);

            string ActualString = LIHashWithKey.ComputeString(TestConstants.DefaultData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.",
                ExpectedString, ActualString));
        }
    }
}