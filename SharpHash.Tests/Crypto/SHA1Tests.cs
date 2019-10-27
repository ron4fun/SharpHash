using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class SHA1Tests : CryptoHashBaseTests
    {
        static SHA1Tests()
        {
            hash = HashFactory.Crypto.CreateSHA1();

            ExpectedHashOfEmptyData = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
            ExpectedHashOfDefaultData = "C8389876E94C043C47BA4BFF3D359884071DC310";
            ExpectedHashOfOnetoNine = "F7C3BC1D808E04732ADF679965CCC34CA7AE3441";
            ExpectedHashOfabcde = "03DE6C570BFE24BFC328CCD7CA46B76EADAF4334";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "E70699720F4222E3A4A4474F14F13CBC3316D9B2";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "CD409025AA5F34ABDC660856463155B23C89B16A";
        }
    }
}