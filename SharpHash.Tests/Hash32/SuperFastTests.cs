using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class SuperFastTests : HashAdapter1BaseTests
    {
        public SuperFastTests()
        {
            hash = HashFactory.Hash32.CreateSuperFast();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "F00EB3C0";
            ExpectedHashOfOnetoNine = "9575A2E9";
            ExpectedHashOfabcde = "51ED072E";
        }
    }
}