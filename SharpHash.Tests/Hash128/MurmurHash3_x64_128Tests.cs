using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace SharpHash.Hash128.Tests
{
    [TestClass]
    public class MurmurHash3_x64_128Tests
    {
        protected IHash hash = HashFactory.Hash128.CreateMurmurHash3_x64_128();

        protected string ExpectedHashOfEmptyData = "00000000000000000000000000000000";
        protected string ExpectedHashOfDefaultData = "705BD3C954B94BE056F06B68662E6364";
        protected string ExpectedHashOfRandomString = "D30654ABBD8227E367D73523F0079673";
        protected string ExpectedHashOfZerotoFour = "0F04E459497F3FC1ECCC6223A28DD613";
        protected string ExpectedHashOfEmptyDataWithOneAsKey = "4610ABE56EFF5CB551622DAA78F83583";
        protected string ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "ADFD14988FB1F8582A1B67C1BBACC218";

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
                ExpectedString = HashFactory.Hash128.CreateMurmurHash3_x64_128().ComputeBytes(temp).ToString();

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

            string ActualString = LIHashWithKey.ComputeString(TestConstants.EmptyData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedString, ActualString);
        }

        [TestMethod]
        public void TestWithDifferentKeyMaxUInt32DefaultData()
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
