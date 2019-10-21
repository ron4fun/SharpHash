using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class BernsteinTests : Hash32BaseTests
    {
        public BernsteinTests()
        {
            hash = HashFactory.Hash32.CreateBernstein();

            ExpectedHashOfEmptyData = "00001505";
            ExpectedHashOfDefaultData = "C4635F48";
            ExpectedHashOfOnetoNine = "35CDBB82";
            ExpectedHashOfabcde = "0F11B894";
        }
    }
}