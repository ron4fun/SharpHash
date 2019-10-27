using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class RIPEMD256Tests : CryptoHashBaseTests
    {
        static RIPEMD256Tests()
        {
            hash = HashFactory.Crypto.CreateRIPEMD256();

            ExpectedHashOfEmptyData = "02BA4C4E5F8ECD1877FC52D64D30E37A2D9774FB1E5D026380AE0168E3C5522D";
            ExpectedHashOfDefaultData = "95EF1FFAB0EF6229F58CAE347426ADE3C412BCEB1057DAED0062BBDEE4BEACC6";
            ExpectedHashOfOnetoNine = "6BE43FF65DD40EA4F2FF4AD58A7C1ACC7C8019137698945B16149EB95DF244B7";
            ExpectedHashOfabcde = "81D8B58A3110A9139B4DDECCB031409E8AF023067CF4C6F0B701DAB9ECC0EB4E";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "F1149704222B7ABA1F9C14B0E9A67909C53605E07614CF8C47CB357083EA3A6B";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "D59B820A708FA31C39BD33BA88CB9A25516A3BA2BA99A74223FCE0EC0F9BFB1B";
        }
    }
}