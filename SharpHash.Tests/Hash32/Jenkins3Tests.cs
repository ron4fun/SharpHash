using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class Jenkins3Tests : HashAdapter1BaseTests
    {
        public Jenkins3Tests()
        {
            hash = HashFactory.Hash32.CreateJenkins3();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "F0F69CEF";
            ExpectedHashOfOnetoNine = "845D9A96";
            ExpectedHashOfabcde = "026D72DE";
        }
    }
}