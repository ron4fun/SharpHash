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
    public class XXHash64Tests
    {
        protected IHash hash = HashFactory.Hash64.CreateXXHash64();

        protected string ExpectedHashOfEmptyData = "EF46DB3751D8E999";
        protected string ExpectedHashOfDefaultData = "0F1FADEDD0B77861";
        protected string ExpectedHashOfRandomString = "C9C17BCD07584404";
        protected string ExpectedHashOfZerotoFour = "34CB4C2EE6166F65";
        protected string ExpectedHashOfEmptyDataWithOneAsKey = "D5AFBA1336A3BE4B";
        protected string ExpectedHashOfDefaultDataWithMaxUInt64AsKey = "68DCC1056096A94F";

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

            ChunkedDataBytes = Converters.ConvertStringToBytes(TestConstants.ChunkedData,
                Encoding.UTF8);
            for (i = 0; i < ChunkedDataBytes.Length; i++)
            {
                Count = ChunkedDataBytes.Length - i;

                temp = new byte[Count];
                Utils.Utils.memcopy(ref temp, ChunkedDataBytes, Count, i);

                hash.Initialize();

                hash.TransformBytes(ChunkedDataBytes, i, Count);

                ActualString = hash.TransformFinal().ToString();
                ExpectedString = HashFactory.Hash64.CreateXXHash64().ComputeBytes(temp).ToString();

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
            LIHashWithKey = (hash as IHashWithKey);
            LIHashWithKey.Key = Converters.ReadUInt64AsBytesLE(UInt64.MaxValue);

            string ActualString = LIHashWithKey.ComputeString(TestConstants.DefaultData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedString, ActualString);
        }

    }

}
