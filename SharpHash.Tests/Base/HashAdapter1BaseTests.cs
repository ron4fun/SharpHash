using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Tests;

namespace SharpHash
{
    [TestClass]
    public abstract class HashAdapter1BaseTests : HashBaseTests
    {
        protected string ExpectedHashOfOnetoNine { get; set; }
        protected string ExpectedHashOfabcde { get; set; }

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
    }
}