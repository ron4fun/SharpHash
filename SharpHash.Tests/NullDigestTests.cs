using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System.Linq;
using System.Text;

namespace SharpHash.Tests
{
    [TestClass]
    public class NullDigestTests
    {
        protected static IHash hash = HashFactory.NullDigestFactory.CreateNullDigest();

        protected static string ExpectedHashOfEmptyData = "00000001";
        protected static string ExpectedHashOfDefaultData = "25D40524";
        protected static string ExpectedHashOfOnetoNine = "091E01DE";
        protected static string ExpectedHashOfabcde = "05C801F0";

        [TestMethod]
        public void TestBytesabcde()
        {
            byte[] BytesABCDE, Result;

            BytesABCDE = Converters.ConvertStringToBytes("abcde", Encoding.UTF8);

            hash.Initialize();

            hash.TransformBytes(BytesABCDE);

            Result = hash.TransformFinal().GetBytes();

            Assert.IsTrue(Enumerable.SequenceEqual(BytesABCDE, Result));
        }

        [TestMethod]
        public void TestEmptyBytes()
        {
            byte[] BytesEmpty, Result;

            BytesEmpty = Converters.ConvertStringToBytes("", Encoding.UTF8);

            hash.Initialize();

            hash.TransformBytes(BytesEmpty);

            Result = hash.TransformFinal().GetBytes();

            Assert.IsTrue(Enumerable.SequenceEqual(BytesEmpty, Result));
        }

        [TestMethod]
        public void TestForNullBytes()
        {
            TestHelper.TestForNullBytes(hash);
        }

        [TestMethod]
        public void TestIncrementalHash()
        {
            byte[] BytesZeroToNine, Result, Temp;

            BytesZeroToNine = Converters.ConvertStringToBytes("0123456789", Encoding.UTF8);

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