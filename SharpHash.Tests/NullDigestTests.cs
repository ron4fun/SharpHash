using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;

namespace SharpHash.Checksum.Tests
{
    [TestClass]
    public class NullDigestTests
    {     
        protected IHash nullDigest = new NullDigest();

        protected string ExpectedHashOfEmptyData = "00000001";
        protected string ExpectedHashOfDefaultData = "25D40524";
        protected string ExpectedHashOfOnetoNine = "091E01DE";
        protected string ExpectedHashOfabcde = "05C801F0";

        [TestMethod]
        public void TestBytesabcde()
        {
            byte[] BytesABCDE, Result;

            BytesABCDE = Converters.ConvertStringToBytes("abcde");
            Assert.AreEqual(-1, nullDigest.BlockSize);
            Assert.AreEqual(-1, nullDigest.HashSize);

            nullDigest.Initialize();

            Assert.AreEqual(0, nullDigest.BlockSize);
            Assert.AreEqual(0, nullDigest.HashSize);

            nullDigest.TransformBytes(BytesABCDE);

            Assert.AreEqual(0, nullDigest.BlockSize);
            Assert.AreEqual(BytesABCDE.Length, nullDigest.HashSize);

            Result = nullDigest.TransformFinal().GetBytes();

            Assert.AreEqual(0, nullDigest.BlockSize);
            Assert.AreEqual(0, nullDigest.HashSize);

            Assert.IsTrue(Enumerable.SequenceEqual(BytesABCDE, Result));
        }

        [TestMethod]
        public void TestEmptyBytes()
        {
            byte[] BytesEmpty, Result;

            nullDigest = new NullDigest();

            BytesEmpty = Converters.ConvertStringToBytes("");
            Assert.AreEqual(-1, nullDigest.BlockSize);
            Assert.AreEqual(-1, nullDigest.HashSize);

            nullDigest.Initialize();

            Assert.AreEqual(0, nullDigest.BlockSize);
            Assert.AreEqual(0, nullDigest.HashSize);

            nullDigest.TransformBytes(BytesEmpty);

            Assert.AreEqual(0, nullDigest.BlockSize);
            Assert.AreEqual(BytesEmpty.Length, nullDigest.HashSize);

            Result = nullDigest.TransformFinal().GetBytes();

            Assert.AreEqual(0, nullDigest.BlockSize);
            Assert.AreEqual(0, nullDigest.HashSize);

            Assert.IsTrue(Enumerable.SequenceEqual(BytesEmpty, Result));
        }

        [TestMethod]
        public void TestIncrementalHash()
        {
            byte[] BytesZeroToNine, Result, Temp;

            nullDigest = new NullDigest();

            BytesZeroToNine = Converters.ConvertStringToBytes("0123456789");
            Assert.AreEqual(-1, nullDigest.BlockSize);
            Assert.AreEqual(-1, nullDigest.HashSize);

            nullDigest.Initialize();

            Assert.AreEqual(0, nullDigest.BlockSize);
            Assert.AreEqual(0, nullDigest.HashSize);

            Temp = new byte[4];
            Utils.Utils.memcopy(Temp, BytesZeroToNine, 4);

            nullDigest.TransformBytes(Temp);

            Assert.AreEqual(0, nullDigest.BlockSize);
            Assert.AreEqual(4, nullDigest.HashSize);

            Temp = new byte[6];
            Utils.Utils.memcopy(Temp, BytesZeroToNine, 6, 4);
            
            nullDigest.TransformBytes(Temp);

            Assert.AreEqual(0, nullDigest.BlockSize);
            Assert.AreEqual(10, nullDigest.HashSize);

            Result = nullDigest.TransformFinal().GetBytes();

            Assert.AreEqual(0, nullDigest.BlockSize);
            Assert.AreEqual(0, nullDigest.HashSize);

            Assert.IsTrue(Enumerable.SequenceEqual(BytesZeroToNine, Result));
        }

        [TestMethod]
        public void TestHashCloneIsCorrect()
        {
            TestHelper.TestHashCloneIsCorrect(new NullDigest());
        }

        [TestMethod]
        public void TestHashCloneIsUnique()
        {
            TestHelper.TestHashCloneIsUnique(new NullDigest());
        }
        
    }

}
