using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class RIPEMD128Tests : CryptoHashBaseTests
    {
        static RIPEMD128Tests()
        {
            hash = HashFactory.Crypto.CreateRIPEMD128();

            ExpectedHashOfEmptyData = "CDF26213A150DC3ECB610F18F6B38B46";
            ExpectedHashOfDefaultData = "75891B00B2874EDCAF7002CA98264193";
            ExpectedHashOfOnetoNine = "1886DB8ACDCBFEAB1E7EE3780400536F";
            ExpectedHashOfabcde = "A0A954BE2A779BFB2129B72110C5782D";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "E93930A64EF6807C4D80EF30DF86AFA7";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "BA844D13A1215E20634A49D5599197EF";
        }
    }
}