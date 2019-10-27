using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Keccak_224Tests : CryptoHashBaseTests
    {
        static Keccak_224Tests()
        {
            hash = HashFactory.Crypto.CreateKeccak_224();

            ExpectedHashOfEmptyData = "F71837502BA8E10837BDD8D365ADB85591895602FC552B48B7390ABD";
            ExpectedHashOfDefaultData = "1BA678212F840E95F076B4E3E75310D4DA4308E04396E07EF1683ACE";
            ExpectedHashOfOnetoNine = "06471DE6C635A88E7470284B2C2EBF9BD7E5E888CBBD128C21CB8308";
            ExpectedHashOfabcde = "16F91F7E036DF526340440C34C231862D8F6319772B670EEFD4703FF";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "8C500F95CB013CBC16DEB6CB742D470E20404E0A1776647EAAB6E869";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "D6CE783743A36717F893DFF82DE89633F21089AFBE4F26431E269650";
        }
    }
}