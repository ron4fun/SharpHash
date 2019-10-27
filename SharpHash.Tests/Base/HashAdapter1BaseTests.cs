using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Tests;

namespace SharpHash
{
    [TestClass]
    public abstract class HashAdapter1BaseTests : HashBaseTests
    {
        protected static string ExpectedHashOfOnetoNine { get; set; }
        protected static string ExpectedHashOfabcde { get; set; }

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