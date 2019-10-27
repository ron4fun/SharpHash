using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class Bernstein1Tests : HashAdapter1BaseTests
    {
        static Bernstein1Tests()
        {
            hash = HashFactory.Hash32.CreateBernstein1();

            ExpectedHashOfEmptyData = "00001505";
            ExpectedHashOfDefaultData = "2D122E48";
            ExpectedHashOfOnetoNine = "3BABEA14";
            ExpectedHashOfabcde = "0A1DEB04";
        }
    }
}