using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class SHA0Tests : CryptoHashBaseTests
    {
        static SHA0Tests()
        {
            hash = HashFactory.Crypto.CreateSHA0();

            ExpectedHashOfEmptyData = "F96CEA198AD1DD5617AC084A3D92C6107708C0EF";
            ExpectedHashOfDefaultData = "C9CBBE593DE122CA36B13CC37FE2CA8D5606FEED";
            ExpectedHashOfOnetoNine = "F0360779D2AF6615F306BB534223CF762A92E988";
            ExpectedHashOfabcde = "D624E34951BB800F0ACAE773001DF8CFFE781BA8";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "CDA87167A558311B9154F372F21A453030BBE16A";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "EAA73E85DCAC5BAD0A0E71C0695F901FC32DB38A";
        }
    }
}