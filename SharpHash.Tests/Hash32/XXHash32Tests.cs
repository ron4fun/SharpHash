using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class XXHash32Tests
    {
        protected IHash hash = HashFactory.Hash32.CreateXXHash32();

        protected string ExpectedHashOfEmptyData = "02CC5D05";
        protected string ExpectedHashOfDefaultData = "6A1C7A99";
        protected string ExpectedHashOfRandomString = "CE8CF448";
        protected string ExpectedHashOfZerotoFour = "8AA3B71C";
        protected string ExpectedHashOfEmptyDataWithOneAsKey = "0B2CB792";
        protected string ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "728C6772";

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
        public void TestRandomString()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.RandomStringTobacco,
                ExpectedHashOfRandomString, hash);
        }

        [TestMethod]
        public void TestZerotoFour()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.ZerotoFour,
                ExpectedHashOfZerotoFour, hash);
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
        public void TestIndexChunkedDataIncrementalHash()
        {
            Int32 Count, i;
            byte[] temp, ChunkedDataBytes;
            string ActualString, ExpectedString;

            ChunkedDataBytes = Converters.ConvertStringToBytes(TestConstants.ChunkedData);
            for (i = 0; i < ChunkedDataBytes.Length; i++)
            {
                Count = ChunkedDataBytes.Length - i;

                temp = new byte[Count];
                Utils.Utils.memcopy(ref temp, ChunkedDataBytes, Count, i);

                hash.Initialize();

                hash.TransformBytes(ChunkedDataBytes, i, Count);

                ActualString = hash.TransformFinal().ToString();
                ExpectedString = HashFactory.Hash32.CreateXXHash32().ComputeBytes(temp).ToString();

                Assert.AreEqual(ExpectedString, ActualString);
            }
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
        public void TestWithDifferentKeyOneEmptyString()
        {
            IHashWithKey LIHashWithKey;

            string ExpectedString = ExpectedHashOfEmptyDataWithOneAsKey;
            LIHashWithKey = (hash as IHashWithKey);
            LIHashWithKey.Key = Converters.ReadUInt32AsBytesLE((UInt32)1);

            string ActualString = LIHashWithKey.ComputeString(TestConstants.EmptyData).ToString();

            Assert.AreEqual(ExpectedString, ActualString);
        }

        [TestMethod]
        public void TestWithDifferentKeyMaxUInt32DefaultData()
        {
            IHashWithKey LIHashWithKey;
            
            string ExpectedString = ExpectedHashOfDefaultDataWithMaxUInt32AsKey;
            LIHashWithKey = (hash as IHashWithKey);
            LIHashWithKey.Key = Converters.ReadUInt32AsBytesLE(UInt32.MaxValue);

            string ActualString = LIHashWithKey.ComputeString(TestConstants.DefaultData).ToString();

            Assert.AreEqual(ExpectedString, ActualString);
        }

    }

}
