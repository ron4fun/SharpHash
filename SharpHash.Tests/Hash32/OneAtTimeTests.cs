using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class OneAtTimeTests : Hash32BaseTests
    {
        public OneAtTimeTests()
        {
            hash = HashFactory.Hash32.CreateOneAtTime();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "4E379A4F";
            ExpectedHashOfOnetoNine = "C66B58C5";
            ExpectedHashOfabcde = "B98559FC";
        }
    }
}