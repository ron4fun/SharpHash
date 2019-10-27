using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Grindahl256Tests : CryptoHashBaseTests
    {
        static Grindahl256Tests()
        {
            hash = HashFactory.Crypto.CreateGrindahl256();

            ExpectedHashOfEmptyData = "45A7600159AF54AE110FCB6EA0F38AD57875EAC814F74D2CBC247D28C89923E6";
            ExpectedHashOfDefaultData = "AC72E90B0F3F5864A0AF3C43E2A73E393DEBF22AB81B6786ADE22B4517DAAAB6";
            ExpectedHashOfOnetoNine = "D2460846C5FE9E4750985CC9244D2458BEFD884435121FE56528022A3C7605B7";
            ExpectedHashOfabcde = "5CDA73422F36E41087795BB6C21D577BAAF114E4A6CCF33D919E700EE2489FE2";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "02D964EE346B0C333CEC0F5D7E68C5CFAAC1E3CB0C06FE36418E17AA3AFCA2BE";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "65BA6F8EFA5B566D556EC8E3A2EC67DB7EE9BDEE663F17A8B8E7FAD067481023";
        }
    }
}