using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SharpHash.Checksum.Tests
{
    [TestClass]
    public class Adler32Tests
    {     
        protected IHash hash = HashFactory.Checksum.CreateAdler32();

        protected string ExpectedHashOfEmptyData = "00000001";
        protected string ExpectedHashOfDefaultData = "25D40524";
        protected string ExpectedHashOfOnetoNine = "091E01DE";
        protected string ExpectedHashOfabcde = "05C801F0";

        [TestMethod]
        public void TestBytesabcde()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.Bytesabcde,
                ExpectedHashOfabcde, hash);
        }

        [TestMethod]
        public void TestDefaultData()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.DefaultData,
                ExpectedHashOfDefaultData, hash);
        }

        [TestMethod]
        public void TestEmptyString()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.EmptyData,
                ExpectedHashOfEmptyData, hash);
        }

        [TestMethod]
        public void TestOnetoNine()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.OnetoNine,
                ExpectedHashOfOnetoNine, hash);
        }

        [TestMethod]
        public void TestHashCloneIsCorrect()
        {
            TestHelper.TestHashCloneIsCorrect(hash);
        }

        [TestMethod]
        public void TestIncrementalHash()
        {
            TestHelper.TestIncrementalHash(TestConstants.DefaultData,
                ExpectedHashOfDefaultData, hash);
        }

        [TestMethod]
        public void TestHashCloneIsUnique()
        {
            TestHelper.TestHashCloneIsUnique(hash);
        }

        [TestMethod]
        public void TestEmptyStream()
        {
            TestHelper.TestEmptyStream(ExpectedHashOfEmptyData, hash);        
        }

    }

}
