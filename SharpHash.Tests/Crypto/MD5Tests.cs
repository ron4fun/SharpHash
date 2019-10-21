using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class MD5Tests : CryptoHashBaseTests
    {
        public MD5Tests()
        {
            hash = HashFactory.Crypto.CreateMD5();

            ExpectedHashOfEmptyData = "D41D8CD98F00B204E9800998ECF8427E";
            ExpectedHashOfDefaultData = "462EC1E50C8F2D5C387682E98F9BC842";
            ExpectedHashOfOnetoNine = "25F9E794323B453885F5181F1B624D0B";
            ExpectedHashOfabcde = "AB56B4D92B40713ACC5AF89985D4B786";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "696D0706C43816B551D874B9B3E4B7E6";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "09F705F43799213192622CCA6DF68941";
        }
    }
}