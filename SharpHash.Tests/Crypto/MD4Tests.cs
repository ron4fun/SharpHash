using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class MD4Tests : CryptoHashBaseTests
    {
        static MD4Tests()
        {
            hash = HashFactory.Crypto.CreateMD4();

            ExpectedHashOfEmptyData = "31D6CFE0D16AE931B73C59D7E0C089C0";
            ExpectedHashOfDefaultData = "A77EAB8C3432FD9DD1B87C3C5C2E9C3C";
            ExpectedHashOfOnetoNine = "2AE523785D0CAF4D2FB557C12016185C";
            ExpectedHashOfabcde = "9803F4A34E8EB14F96ADBA49064A0C41";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "7E30F4DA95992DBA450E345641DE5CEC";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "BF21F9EC05E480EEDB12AF20181713E3";
        }
    }
}