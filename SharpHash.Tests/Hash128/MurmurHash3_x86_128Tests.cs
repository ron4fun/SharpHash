using SharpHash.Hash128;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;

namespace SharpHash.Hash128.Tests
{
    [TestClass]
    public class MurmurHash3_x86_128Tests
    {
        protected IHash hash = new MurmurHash3_x86_128();

        protected string ExpectedHashOfEmptyData = "00000000000000000000000000000000";
        protected string ExpectedHashOfDefaultData = "B35E1058738E067BF637B17075F14B8B";
        protected string ExpectedHashOfRandomString = "9B5B7BA2EF3F7866889ADEAF00F3F98E";
        protected string ExpectedHashOfZerotoFour = "35C5B3EE7B3B211600AE108800AE1088";
        protected string ExpectedHashOfEmptyDataWithOneAsKey = "88C4ADEC54D201B954D201B954D201B9";
        protected string ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "55315FA9E8129C7390C080B8FDB1C972";

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
                Utils.Utils.memcopy(temp, ChunkedDataBytes, Count, i);

                hash.Initialize();

                hash.TransformBytes(ChunkedDataBytes, i, Count);

                ActualString = hash.TransformFinal().ToString();
                ExpectedString = new MurmurHash3_x86_128().ComputeBytes(temp).ToString();

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
