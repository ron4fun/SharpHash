using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class ShiftAndXorTests : HashAdapter1BaseTests
    {
        static ShiftAndXorTests()
        {
            hash = HashFactory.Hash32.CreateShiftAndXor();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "BD0A7DA4";
            ExpectedHashOfOnetoNine = "E164F745";
            ExpectedHashOfabcde = "0731B823";
        }
    }
}