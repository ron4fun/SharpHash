using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Tests;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class MurmurHash3_x86_32Tests : HashWithUInt32AsKeyBaseTests
    {
        public MurmurHash3_x86_32Tests()
        {
            hash = HashFactory.Hash32.CreateMurmurHash3_x86_32();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "3D97B9EB";
            ExpectedHashOfRandomString = "A8D02B9A";
            ExpectedHashOfZerotoFour = "19D02170";
            ExpectedHashOfEmptyDataWithOneAsKey = "514E28B7";
            ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "B05606FE";
        }

        [TestMethod]
        new public void TestRandomString()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.RandomStringRecord,
                ExpectedHashOfRandomString, hash);
        }
    }
}