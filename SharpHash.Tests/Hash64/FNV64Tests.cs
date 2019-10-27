using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash64.Tests
{
    [TestClass]
    public class FNV64Tests : HashAdapter1BaseTests
    {
        static FNV64Tests()
        {
            hash = HashFactory.Hash64.CreateFNV();

            ExpectedHashOfEmptyData = "0000000000000000";
            ExpectedHashOfDefaultData = "061A6856F5925B83";
            ExpectedHashOfOnetoNine = "B8FB573C21FE68F1";
            ExpectedHashOfabcde = "77018B280326F529";
        }
    }
}