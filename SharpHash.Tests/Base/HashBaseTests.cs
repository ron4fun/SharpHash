using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System;
using System.Text;

namespace SharpHash
{
    [TestClass]
    public abstract class HashBaseTests : XOFBaseTests
    {
        protected IHash hash { get; set; }

        protected string ExpectedHashOfEmptyData { get; set; }
        protected string ExpectedHashOfDefaultData { get; set; }

        [TestMethod]
        public void TestEmptyString()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.EmptyData,
                ExpectedHashOfEmptyData, hash);
        }

        [TestMethod]
        public void TestForNullBytes()
        {
            TestHelper.TestForNullBytes(hash);
        }

        [TestMethod]
        public void TestDefaultData()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.DefaultData,
            ExpectedHashOfDefaultData, hash);
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
                ExpectedString = hash.ComputeBytes(temp).ToString();

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
    }
}