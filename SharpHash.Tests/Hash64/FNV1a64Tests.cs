using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash64.Tests
{
    [TestClass]
    public class FNV1a64Tests : HashAdapter1BaseTests
    {
        public FNV1a64Tests()
        {
            hash = HashFactory.Hash64.CreateFNV1a();

            ExpectedHashOfEmptyData = "CBF29CE484222325";
            ExpectedHashOfDefaultData = "5997E22BF92B0598";
            ExpectedHashOfOnetoNine = "06D5573923C6CDFC";
            ExpectedHashOfabcde = "6348C52D762364A8";
        }
    }
}