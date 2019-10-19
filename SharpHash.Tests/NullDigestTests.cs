using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;

namespace SharpHash.Checksum.Tests
{
    [TestClass]
    public class NullDigestTests
    {     
        protected IHash hash = HashFactory.NullDigestFactory.CreateNullDigest();

        protected string ExpectedHashOfEmptyData = "00000001";
        protected string ExpectedHashOfDefaultData = "25D40524";
        protected string ExpectedHashOfOnetoNine = "091E01DE";
        protected string ExpectedHashOfabcde = "05C801F0";

        [TestMethod]
        public void TestBytesabcde()
        {
            byte[] BytesABCDE, Result;

            BytesABCDE = Converters.ConvertStringToBytes("abcde");
            
            hash.Initialize();
            
            hash.TransformBytes(BytesABCDE);
            
            Result = hash.TransformFinal().GetBytes();          

            Assert.IsTrue(Enumerable.SequenceEqual(BytesABCDE, Result));

            Assert.ThrowsException<NotImplementedHashLibException>(() => hash.BlockSize);
            Assert.ThrowsException<NotImplementedHashLibException>(() => hash.HashSize);
        }

        [TestMethod]
        public void TestEmptyBytes()
        {
            byte[] BytesEmpty, Result;
            
            BytesEmpty = Converters.ConvertStringToBytes("");

            hash.Initialize();

            hash.TransformBytes(BytesEmpty);

            Result = hash.TransformFinal().GetBytes();
            
            Assert.IsTrue(Enumerable.SequenceEqual(BytesEmpty, Result));

            Assert.ThrowsException<NotImplementedHashLibException>(() => hash.BlockSize);
            Assert.ThrowsException<NotImplementedHashLibException>(() => hash.HashSize);
        }

        [TestMethod]
        public void TestIncrementalHash()
        {
            byte[] BytesZeroToNine, Result, Temp;

            BytesZeroToNine = Converters.ConvertStringToBytes("0123456789");
            
            hash.Initialize();
            
            Temp = new byte[4];
            Utils.Utils.memcopy(ref Temp, BytesZeroToNine, 4);

            hash.TransformBytes(Temp);
            
            Temp = new byte[6];
            Utils.Utils.memcopy(ref Temp, BytesZeroToNine, 6, 4);
            
            hash.TransformBytes(Temp);

            Result = hash.TransformFinal().GetBytes();

            Assert.IsTrue(Enumerable.SequenceEqual(BytesZeroToNine, Result));

            Assert.ThrowsException<NotImplementedHashLibException>(() => hash.BlockSize);
            Assert.ThrowsException<NotImplementedHashLibException>(() => hash.HashSize);
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
