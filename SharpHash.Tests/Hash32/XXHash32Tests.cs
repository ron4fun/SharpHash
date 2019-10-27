using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class XXHash32Tests : HashWithUInt32AsKeyBaseTests
    {
        static XXHash32Tests()
        {
            hash = HashFactory.Hash32.CreateXXHash32();

            ExpectedHashOfEmptyData = "02CC5D05";
            ExpectedHashOfDefaultData = "6A1C7A99";
            ExpectedHashOfRandomString = "CE8CF448";
            ExpectedHashOfZerotoFour = "8AA3B71C";
            ExpectedHashOfEmptyDataWithOneAsKey = "0B2CB792";
            ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "728C6772";
        }
    }
}