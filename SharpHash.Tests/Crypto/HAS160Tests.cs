using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class HAS160Tests : CryptoHashBaseTests
    {
        static HAS160Tests()
        {
            hash = HashFactory.Crypto.CreateHAS160();

            ExpectedHashOfEmptyData = "307964EF34151D37C8047ADEC7AB50F4FF89762D";
            ExpectedHashOfDefaultData = "2773EDAC4501514254D7B1DF091D6B7652250A52";
            ExpectedHashOfOnetoNine = "A0DA48CCD36C9D24AA630D4B3673525E9109A83C";
            ExpectedHashOfabcde = "EEEA94C2F0450B639BC2ACCAF4AEB172A5885313";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "7D2F0051F2BD817A4C27F126882353BCD300B7CA";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "53970A7AC510A85D0E22FF506FED5B57188A8B3F";
        }
    }
}