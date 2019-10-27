using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class MD2Tests : CryptoHashBaseTests
    {
        static MD2Tests()
        {
            hash = HashFactory.Crypto.CreateMD2();

            ExpectedHashOfEmptyData = "8350E5A3E24C153DF2275C9F80692773";
            ExpectedHashOfDefaultData = "DFBE28FF5A3C23CAA85BE5848F16524E";
            ExpectedHashOfOnetoNine = "12BD4EFDD922B5C8C7B773F26EF4E35F";
            ExpectedHashOfabcde = "DFF9959487649F5C7AF5D0680A9A5D22";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "03D7546FEADF29A91CEB40290A27E081";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "C5F4625462CD5CF7723C19E8566F6790";
        }
    }
}