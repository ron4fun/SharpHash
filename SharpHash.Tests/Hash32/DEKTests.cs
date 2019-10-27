using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class DEKTests : HashAdapter1BaseTests
    {
        static DEKTests()
        {
            hash = HashFactory.Hash32.CreateDEK();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "8E01E947";
            ExpectedHashOfOnetoNine = "AB4ACBA5";
            ExpectedHashOfabcde = "0C2080E5";
        }
    }
}