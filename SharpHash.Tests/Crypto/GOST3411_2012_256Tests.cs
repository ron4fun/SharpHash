using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Tests;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class GOST3411_2012_256Tests : HashBaseTests
    {
        private string ExpectedHashOfQuickBrownFox { get; set; }

        public GOST3411_2012_256Tests()
        {
            hash = HashFactory.Crypto.CreateGOST3411_2012_256();

            ExpectedHashOfEmptyData = "3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB";
            ExpectedHashOfQuickBrownFox = "3E7DEA7F2384B6C5A3D0E24AAA29C05E89DDD762145030EC22C71A6DB8B2C1F4";
        }

        [TestMethod]
        public new void TestDefaultData() // For QuickBrownFox
        {
            TestHelper.TestActualAndExpectedData(TestConstants.QuickBrownDog,
            ExpectedHashOfQuickBrownFox, hash);
        }

        [TestMethod]
        public new void TestIncrementalHash()
        {
            TestHelper.TestIncrementalHash(TestConstants.QuickBrownDog,
            ExpectedHashOfQuickBrownFox, hash.Clone());
        }

        [TestMethod]
        public void TestHMACCloneIsCorrect()
        {
            TestHelper.TestHMACCloneIsCorrect(hash);
        }
    }
}