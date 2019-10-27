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
    public class Murmur2_64Tests : HashAdapter1BaseTests
    {
        private string ExpectedHashOfDefaultDataWithMaxUInt32AsKey { get; set; }

        public Murmur2_64Tests()
        {
            hash = HashFactory.Hash64.CreateMurmur2();

            ExpectedHashOfEmptyData = "0000000000000000";
            ExpectedHashOfDefaultData = "F78F3AF068158F5A";
            ExpectedHashOfOnetoNine = "F22BE622518FAF39";
            ExpectedHashOfabcde = "AF7BA284707E90C2";
            ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "49F2E215E924B552";
        }

        [TestMethod]
        public void TestWithDifferentKey()
        {
            IHashWithKey LIHashWithKey;

            string ExpectedString = ExpectedHashOfDefaultDataWithMaxUInt32AsKey;
            LIHashWithKey = (hash.Clone() as IHashWithKey);
            LIHashWithKey.Key = Converters.ReadUInt32AsBytesLE(UInt32.MaxValue);

            string ActualString = LIHashWithKey.ComputeString(TestConstants.DefaultData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedString, ActualString);
        }
    }
}