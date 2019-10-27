using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class SHA2_224Tests : CryptoHashBaseTests
    {
        static SHA2_224Tests()
        {
            hash = HashFactory.Crypto.CreateSHA2_224();

            ExpectedHashOfEmptyData = "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F";
            ExpectedHashOfDefaultData = "DF2B86ED008508F542443C4B1810AA5A0F5658692B808EEB1D0A2F7E";
            ExpectedHashOfOnetoNine = "9B3E61BF29F17C75572FAE2E86E17809A4513D07C8A18152ACF34521";
            ExpectedHashOfabcde = "BDD03D560993E675516BA5A50638B6531AC2AC3D5847C61916CFCED6";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "86855E59D8B09A3C7632D4E176C4B65C549255F417FEF9EEF2D4167D";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "EC47E83DB5DD735EBB7AA4A898460950B16A3A0FA48E4BB9184EA3D1";
        }
    }
}