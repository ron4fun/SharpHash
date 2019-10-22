using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System;
using System.Text;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class Murmur2Tests : HashAdapter1BaseTests
    {
        private string ExpectedHashOfDefaultDataWithMaxUInt32AsKey { get; set; }

        public Murmur2Tests()
        {
            hash = HashFactory.Hash32.CreateMurmur2();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "30512DE6";
            ExpectedHashOfOnetoNine = "DCCB0167";
            ExpectedHashOfabcde = "5F09A8DE";
            ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "B15D52F0";
        }

        [TestMethod]
        public void TestWithDifferentKey()
        {
            IHashWithKey LIHashWithKey;

            string ExpectedString = ExpectedHashOfDefaultDataWithMaxUInt32AsKey;
            LIHashWithKey = (hash as IHashWithKey);
            LIHashWithKey.Key = Converters.ReadUInt32AsBytesLE(UInt32.MaxValue);

            string ActualString = LIHashWithKey.ComputeString(TestConstants.DefaultData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedString, ActualString);
        }
    }
}