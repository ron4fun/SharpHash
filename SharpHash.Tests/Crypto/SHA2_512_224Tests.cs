using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class SHA2_512_224Tests : CryptoHashBaseTests
    {
        public SHA2_512_224Tests()
        {
            hash = HashFactory.Crypto.CreateSHA2_512_224();

            ExpectedHashOfEmptyData = "6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4";
            ExpectedHashOfDefaultData = "7A95749FB7F4489A45275556F5D905D28E1B637DCDD6537336AB6234";
            ExpectedHashOfOnetoNine = "F2A68A474BCBEA375E9FC62EAAB7B81FEFBDA64BB1C72D72E7C27314";
            ExpectedHashOfabcde = "880E79BB0A1D2C9B7528D851EDB6B8342C58C831DE98123B432A4515";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "B932866547894977F6E4C61D137FFC2508C639BA6786F45AC64731C8";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "9BC318A84B90F7FF55C53E3F4B602EAD13BB579EB1794455B29562B4";
        }
    }
}