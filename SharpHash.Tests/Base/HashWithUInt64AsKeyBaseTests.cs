using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System;
using System.Text;

namespace SharpHash
{
    [TestClass]
    public abstract class HashWithUInt64AsKeyBaseTests : HashAdapter2BaseTests
    {
        protected static string ExpectedHashOfDefaultDataWithMaxUInt64AsKey { get; set; }

        [TestMethod]
        public void TestWithDifferentKeyOneEmptyString()
        {
            IHashWithKey LIHashWithKey;

            string ExpectedString = ExpectedHashOfEmptyDataWithOneAsKey;
            LIHashWithKey = (hash.Clone() as IHashWithKey);
            LIHashWithKey.Key = Converters.ReadUInt64AsBytesLE((UInt64)1);

            string ActualString = LIHashWithKey.ComputeString(TestConstants.EmptyData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedString, ActualString);
        }

        [TestMethod]
        public void TestWithDifferentKeyMaxUInt64DefaultData()
        {
            IHashWithKey LIHashWithKey;

            string ExpectedString = ExpectedHashOfDefaultDataWithMaxUInt64AsKey;
            LIHashWithKey = (hash.Clone() as IHashWithKey);
            LIHashWithKey.Key = Converters.ReadUInt64AsBytesLE(UInt64.MaxValue);

            string ActualString = LIHashWithKey.ComputeString(TestConstants.DefaultData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedString, ActualString);
        }
    }
}