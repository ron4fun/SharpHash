using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Tests;

namespace SharpHash.Hash64.Tests
{
    [TestClass]
    public class SipHash2_4Tests : Hash32BaseTests
    {
        private string ExpectedHashOfShortMessage { get; set; }

        public SipHash2_4Tests()
        {
            hash = HashFactory.Hash64.CreateSipHash2_4();

            ExpectedHashOfEmptyData = "726FDB47DD0E0E31";
            ExpectedHashOfDefaultData = "AA43C4288619D24E";
            ExpectedHashOfOnetoNine = "CA60FC96020EFEFD";
            ExpectedHashOfabcde = "A74563E1EA79B873";
            ExpectedHashOfShortMessage = "AE43DFAED1AB1C00";
        }

        [TestMethod]
        public void TestShortMessage()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.ShortMessage,
                ExpectedHashOfShortMessage, hash);
        }
    }
}