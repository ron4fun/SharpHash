using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Checksum.Tests
{
    [TestClass]
    public class Adler32Tests : HashAdapter1BaseTests
    {
        public Adler32Tests()
        {
            hash = HashFactory.Checksum.CreateAdler32();

            ExpectedHashOfEmptyData = "00000001";
            ExpectedHashOfDefaultData = "25D40524";
            ExpectedHashOfOnetoNine = "091E01DE";
            ExpectedHashOfabcde = "05C801F0";
        }
    }
}