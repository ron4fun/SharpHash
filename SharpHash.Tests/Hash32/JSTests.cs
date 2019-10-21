using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class JSTests : Hash32BaseTests
    {
        public JSTests()
        {
            hash = HashFactory.Hash32.CreateJS();

            ExpectedHashOfEmptyData = "4E67C6A7";
            ExpectedHashOfDefaultData = "683AFCFE";
            ExpectedHashOfOnetoNine = "90A4224B";
            ExpectedHashOfabcde = "62E8C8B5";
        }
    }
}