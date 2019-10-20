using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace SharpHash.Hash64.Tests
{
    [TestClass]
    public class Murmur2_64Tests
    {
        protected IHash hash = HashFactory.Hash64.CreateMurmur2();

        protected string ExpectedHashOfEmptyData = "0000000000000000";
        protected string ExpectedHashOfDefaultData = "F78F3AF068158F5A";
        protected string ExpectedHashOfOnetoNine = "F22BE622518FAF39";
        protected string ExpectedHashOfabcde = "AF7BA284707E90C2";
        protected string ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "49F2E215E924B552";

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
