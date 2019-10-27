using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class RadioGatun64Tests : CryptoHashBaseTests
    {
        public RadioGatun64Tests()
        {
            hash = HashFactory.Crypto.CreateRadioGatun64();

            ExpectedHashOfEmptyData = "64A9A7FA139905B57BDAB35D33AA216370D5EAE13E77BFCDD85513408311A584";
            ExpectedHashOfDefaultData = "43B3208CE2E6B23D985087A84BD583F713A9002280BF2785B1EE569B12C15054";
            ExpectedHashOfOnetoNine = "76A565017A42B258F5C8C9D2D9FD4C7347947A659ED142FF61C1BEA592F103C5";
            ExpectedHashOfabcde = "36B4DD23A97424844662E882AD1DA1DBAD8CB435A57F380455393C9FF9DE9D37";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "B9CBBB9FE06144CF5E369BDBBCB2C76EBBE8904061C356BA9A06FE2D96E4037F";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "FA280F80C1323C32AACC7F1CAB3808FE2BB8880F901AE6F03BD14D6D1884B267";
        }
    }
}