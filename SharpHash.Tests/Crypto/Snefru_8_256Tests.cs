using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Snefru_8_256Tests : CryptoHashBaseTests
    {
        static Snefru_8_256Tests()
        {
            hash = HashFactory.Crypto.CreateSnefru_8_256();

            ExpectedHashOfEmptyData = "8617F366566A011837F4FB4BA5BEDEA2B892F3ED8B894023D16AE344B2BE5881";
            ExpectedHashOfDefaultData = "230826DA59215F22AF36663491AECC4872F663722A5A7932428CB8196F7AF78D";
            ExpectedHashOfOnetoNine = "1C7DEDC33125AF7517970B97B635777FFBA8905D7A0B359776E3E683B115F992";
            ExpectedHashOfabcde = "8D2891FC6020D7DC93F7561C0CFDDE26426192B3E364A1F52B634482009DC8C8";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "EEE63DC493FCDAA2F826FFF81DB4BAC53CBBFD933BEA3B65C8BEBB576D921623";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "7E33D94C5A09B2E5F800417128BCF3EF2EDCB971884789A35AE4AA7F13A18147";
        }
    }
}