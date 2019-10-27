using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class FNVTests : HashAdapter1BaseTests
    {
        static FNVTests()
        {
            hash = HashFactory.Hash32.CreateFNV();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "BE611EA3";
            ExpectedHashOfOnetoNine = "D8D70BF1";
            ExpectedHashOfabcde = "B2B39969";
        }
    }
}