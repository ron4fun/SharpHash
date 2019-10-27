using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class ELFTests : HashAdapter1BaseTests
    {
        static ELFTests()
        {
            hash = HashFactory.Hash32.CreateELF();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "01F5B2CC";
            ExpectedHashOfOnetoNine = "0678AEE9";
            ExpectedHashOfabcde = "006789A5";
        }
    }
}