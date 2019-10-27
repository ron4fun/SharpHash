using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class RotatingTests : HashAdapter1BaseTests
    {
        static RotatingTests()
        {
            hash = HashFactory.Hash32.CreateRotating();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "158009D3";
            ExpectedHashOfOnetoNine = "1076548B";
            ExpectedHashOfabcde = "00674525";
        }
    }
}