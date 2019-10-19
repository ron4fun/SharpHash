using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class BernsteinTests
    {
        protected IHash hash = HashFactory.Hash32.CreateBernstein();

        protected string ExpectedHashOfEmptyData = "00001505";
        protected string ExpectedHashOfDefaultData = "C4635F48";
        protected string ExpectedHashOfOnetoNine = "35CDBB82";
        protected string ExpectedHashOfabcde = "0F11B894";

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
        public void TestOnetoNine()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.OnetoNine,
                ExpectedHashOfOnetoNine, hash);
        }

        [TestMethod]
        public void TestBytesabcde()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.Bytesabcde,
                ExpectedHashOfabcde, hash);
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
