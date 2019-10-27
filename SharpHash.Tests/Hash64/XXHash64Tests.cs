using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash64.Tests
{
    [TestClass]
    public class XXHash64Tests : HashWithUInt64AsKeyBaseTests
    {
        static XXHash64Tests()
        {
            hash = HashFactory.Hash64.CreateXXHash64();

            ExpectedHashOfEmptyData = "EF46DB3751D8E999";
            ExpectedHashOfDefaultData = "0F1FADEDD0B77861";
            ExpectedHashOfRandomString = "C9C17BCD07584404";
            ExpectedHashOfZerotoFour = "34CB4C2EE6166F65";
            ExpectedHashOfEmptyDataWithOneAsKey = "D5AFBA1336A3BE4B";
            ExpectedHashOfDefaultDataWithMaxUInt64AsKey = "68DCC1056096A94F";
        }
    }
}