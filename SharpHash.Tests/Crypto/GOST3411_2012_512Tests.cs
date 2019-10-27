using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Tests;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class GOST3411_2012_512Tests : HashBaseTests
    {
        private static string ExpectedHashOfQuickBrownFox { get; set; }

        static GOST3411_2012_512Tests()
        {
            hash = HashFactory.Crypto.CreateGOST3411_2012_512();

            ExpectedHashOfEmptyData = "8E945DA209AA869F0455928529BCAE4679E9873AB707B55315F56CEB98BEF0A7362F715528356EE83CDA5F2AAC4C6AD2BA3A715C1BCD81CB8E9F90BF4C1C1A8A";
            ExpectedHashOfQuickBrownFox = "D2B793A0BB6CB5904828B5B6DCFB443BB8F33EFC06AD09368878AE4CDC8245B97E60802469BED1E7C21A64FF0B179A6A1E0BB74D92965450A0ADAB69162C00FE";
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
            TestHelper.TestHMACCloneIsCorrect(hash.Clone());
        }
    }
}