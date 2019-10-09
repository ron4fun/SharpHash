using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace SharpHash.Checksum.Tests
{
    [TestClass]
    public class Adler32Tests
    {     
        protected IHash adler = new Adler32();

        protected string ExpectedHashOfEmptyData = "00000001";
        protected string ExpectedHashOfDefaultData = "25D40524";
        protected string ExpectedHashOfOnetoNine = "091E01DE";
        protected string ExpectedHashOfabcde = "05C801F0";

        [TestMethod]
        public void TestBytesabcde()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.Bytesabcde,
                ExpectedHashOfabcde, adler);
        }

        [TestMethod]
        public void TestDefaultData()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.DefaultData,
                ExpectedHashOfDefaultData, adler);
        }

        [TestMethod]
        public void TestEmptyString()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.EmptyData,
                ExpectedHashOfEmptyData, adler);
        }

        [TestMethod]
        public void TestOnetoNine()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.OnetoNine,
                ExpectedHashOfOnetoNine, adler);
        }

        [TestMethod]
        public void TestHashCloneIsCorrect()
        {
            IHash Original, Copy;
            byte[] MainData, ChunkOne, ChunkTwo;
            Int32 Count;
            string ExpectedString, ActualString;

            MainData = Converters.ConvertStringToBytes(TestConstants.DefaultData);
            Count = MainData.Length - 3;

            ChunkOne = new byte[Count];
            ChunkTwo = new byte[MainData.Length - Count];

            Utils.Utils.memcopy(ChunkOne, MainData, Count);
            Utils.Utils.memcopy(ChunkTwo, MainData, MainData.Length - Count, Count);

            Original = adler;

            Original.Initialize();

            Original.TransformBytes(ChunkOne);
            
            // Make Copy Of Current State
            Copy = Original.Clone();

            Original.TransformBytes(ChunkTwo);

            ExpectedString = Original.TransformFinal().ToString();

            Copy.TransformBytes(ChunkTwo);
            ActualString = Copy.TransformFinal().ToString();

            Assert.AreEqual(ActualString, ExpectedString);
        }

        [TestMethod]
        public void TestIncrementalHash()
        {
            IHash hash = new Adler32();

            TestHelper.TestIncrementalHash(TestConstants.DefaultData,
                ExpectedHashOfDefaultData, hash);
        }

        [TestMethod]
        public void TestHashCloneIsUnique()
        {
            IHash Original, Copy;
            
            Original = adler;
            Original.Initialize();
            Original.BufferSize = (64 * 1024); // 64Kb
                                                // Make Copy Of Current State
            Copy = Original.Clone();
            Copy.BufferSize = (128 * 1024); // 128Kb

            Assert.AreNotEqual(Original.BufferSize, Copy.BufferSize);
        }

        [TestMethod]
        public void TestEmptyStream()
        {
            Stream stream;
            string ActualString;

            stream = new MemoryStream();
            
            ActualString = adler.ComputeStream(stream).ToString();

            Assert.AreEqual(ExpectedHashOfEmptyData, ActualString);

            stream.Close(); // close stream
        }

    }

}
