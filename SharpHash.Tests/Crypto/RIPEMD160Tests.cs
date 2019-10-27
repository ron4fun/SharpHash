using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class RIPEMD160Tests : CryptoHashBaseTests
    {
        static RIPEMD160Tests()
        {
            hash = HashFactory.Crypto.CreateRIPEMD160();

            ExpectedHashOfEmptyData = "9C1185A5C5E9FC54612808977EE8F548B2258D31";
            ExpectedHashOfDefaultData = "0B8EAC9A2EA1E267750CE639D83A84B92631462B";
            ExpectedHashOfOnetoNine = "D3D0379126C1E5E0BA70AD6E5E53FF6AEAB9F4FA";
            ExpectedHashOfabcde = "973398B6E6C6CFA6B5E6A5173F195CE3274BF828";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "4C373970BDB829BE3B6E0B2D9F510E9C35C9B583";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "76D728D9BF39ED42E0C451A9526E3F0D929F067D";
        }
    }
}