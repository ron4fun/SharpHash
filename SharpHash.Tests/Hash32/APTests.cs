using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class APTests : HashAdapter1BaseTests
    {
        public APTests()
        {
            hash = HashFactory.Hash32.CreateAP();

            ExpectedHashOfEmptyData = "AAAAAAAA";
            ExpectedHashOfDefaultData = "7F14EFED";
            ExpectedHashOfOnetoNine = "C0E86BE5";
            ExpectedHashOfabcde = "7F6A697A";
        }
    }
}