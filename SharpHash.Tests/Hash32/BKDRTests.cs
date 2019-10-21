using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class BKDRTests : Hash32BaseTests
    {
        public BKDRTests()
        {
            hash = HashFactory.Hash32.CreateBKDR();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "29E11B15";
            ExpectedHashOfOnetoNine = "DE43D6D5";
            ExpectedHashOfabcde = "B3EDEA13";
        }
    }
}