using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Tests;

namespace SharpHash
{
    [TestClass]
    public abstract class HashAdapter2BaseTests : HashBaseTests
    {
        protected static string ExpectedHashOfRandomString { get; set; }
        protected static string ExpectedHashOfZerotoFour { get; set; }
        protected static string ExpectedHashOfEmptyDataWithOneAsKey { get; set; }

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
    }
}