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
        private string ExpectedHashOfDefaultDataWithMaxUInt64AsKey { get; set; }

        public Murmur2_64Tests()
        {
            hash = HashFactory.Hash64.CreateMurmur2();

            ExpectedHashOfEmptyData = "0000000000000000";
            ExpectedHashOfDefaultData = "831EFD69DC9E99F9";
            ExpectedHashOfOnetoNine = "4977490251674330";
            ExpectedHashOfabcde = "1182974836D6DBB7";
            ExpectedHashOfDefaultDataWithMaxUInt64AsKey = "FF0A342F0AF9ADC6";
        }

        [TestMethod]
        public void TestWithDifferentKey()
        {
            IHashWithKey LIHashWithKey;

            string ExpectedString = ExpectedHashOfDefaultDataWithMaxUInt64AsKey;
            LIHashWithKey = (hash as IHashWithKey);
            LIHashWithKey.Key = Converters.ReadUInt64AsBytesLE(UInt64.MaxValue);

            string ActualString = LIHashWithKey.ComputeString(TestConstants.DefaultData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.",
                ExpectedString, ActualString));
        }
    }
}