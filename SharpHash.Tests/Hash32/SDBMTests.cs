using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class SDBMTests : HashAdapter1BaseTests
    {
        static SDBMTests()
        {
            hash = HashFactory.Hash32.CreateSDBM();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "3001A5C9";
            ExpectedHashOfOnetoNine = "68A07035";
            ExpectedHashOfabcde = "BD500063";
        }
    }
}