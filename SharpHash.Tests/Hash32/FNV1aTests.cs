using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class FNV1aTests : HashAdapter1BaseTests
    {
        static FNV1aTests()
        {
            hash = HashFactory.Hash32.CreateFNV1a();

            ExpectedHashOfEmptyData = "811C9DC5";
            ExpectedHashOfDefaultData = "1892F1F8";
            ExpectedHashOfOnetoNine = "BB86B11C";
            ExpectedHashOfabcde = "749BCF08";
        }
    }
}