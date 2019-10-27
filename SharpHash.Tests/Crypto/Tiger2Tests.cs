using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Tiger2_3_128Tests : CryptoHashBaseTests
    {
        public Tiger2_3_128Tests()
        {
            hash = HashFactory.Crypto.CreateTiger2_3_128();

            ExpectedHashOfEmptyData = "4441BE75F6018773C206C22745374B92";
            ExpectedHashOfDefaultData = "DEB1924D290E3D5567792A8171BFC44F";
            ExpectedHashOfOnetoNine = "82FAF69673762B9FD8A0C902BDB395C1";
            ExpectedHashOfabcde = "E1F0DAC9E852ECF1270FB691C35506D4";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "9B3B854233FD1AFC80D17179039F6F7B";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "0393C69DD393D9E15C723DFAE88C3059";
        }
    }

    [TestClass]
    public class Tiger2_4_128Tests : CryptoHashBaseTests
    {
        public Tiger2_4_128Tests()
        {
            hash = HashFactory.Crypto.CreateTiger2_4_128();

            ExpectedHashOfEmptyData = "6A7201A47AAC2065913811175553489A";
            ExpectedHashOfDefaultData = "22EE5BFE174B8C1C23361306C3E8F32C";
            ExpectedHashOfOnetoNine = "75B7D71ACD40FE5B5D3263C1F68F4CF5";
            ExpectedHashOfabcde = "9FBB0FBF818C0302890CE373559D2370";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "787FFD7B098895A03139CBEBA0FBCCE8";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "A24C1DD76CACA54D3CB2BDDE5E40D84E";
        }
    }

    [TestClass]
    public class Tiger2_5_128Tests : CryptoHashBaseTests
    {
        public Tiger2_5_128Tests()
        {
            hash = HashFactory.Crypto.CreateTiger2_5_128();

            ExpectedHashOfEmptyData = "61C657CC0C3C147ED90779B36A1E811F";
            ExpectedHashOfDefaultData = "7F71F95B346733E7022D4B85BDA9C51E";
            ExpectedHashOfOnetoNine = "F720446C9BFDC8479D9FA53BC8B9144F";
            ExpectedHashOfabcde = "14F45FAC4BE0302E740CCC6FE99D75A6";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "B0D4AAA0A3239A5B242979DBE02C3373";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "F545BB88FBE3E5FB85E6DE063D081B66";
        }
    }

    [TestClass]
    public class Tiger2_3_160Tests : CryptoHashBaseTests
    {
        public Tiger2_3_160Tests()
        {
            hash = HashFactory.Crypto.CreateTiger2_3_160();

            ExpectedHashOfEmptyData = "4441BE75F6018773C206C22745374B924AA8313F";
            ExpectedHashOfDefaultData = "DEB1924D290E3D5567792A8171BFC44F70B5CD13";
            ExpectedHashOfOnetoNine = "82FAF69673762B9FD8A0C902BDB395C12B0CBDDC";
            ExpectedHashOfabcde = "E1F0DAC9E852ECF1270FB691C35506D4BEDB12A0";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "74B33C922DD679DC7144EF9F6BE807A8F1C370FE";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "71028DCDC197492195110EA5CFF6B3E04912FF25";
        }
    }

    [TestClass]
    public class Tiger2_4_160Tests : CryptoHashBaseTests
    {
        public Tiger2_4_160Tests()
        {
            hash = HashFactory.Crypto.CreateTiger2_4_160();

            ExpectedHashOfEmptyData = "6A7201A47AAC2065913811175553489ADD0F8B99";
            ExpectedHashOfDefaultData = "22EE5BFE174B8C1C23361306C3E8F32C92075577";
            ExpectedHashOfOnetoNine = "75B7D71ACD40FE5B5D3263C1F68F4CF5A5DA963B";
            ExpectedHashOfabcde = "9FBB0FBF818C0302890CE373559D23702D87C69B";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "4C7CE724E7021DF3B53FA997C49E07E4DF9EA0F7";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "283A6ED11043AAA947A12843DC5C4B16283BE633";
        }
    }

    [TestClass]
    public class Tiger2_5_160Tests : CryptoHashBaseTests
    {
        public Tiger2_5_160Tests()
        {
            hash = HashFactory.Crypto.CreateTiger2_5_160();

            ExpectedHashOfEmptyData = "61C657CC0C3C147ED90779B36A1E811F1D27F406";
            ExpectedHashOfDefaultData = "7F71F95B346733E7022D4B85BDA9C51E904825F7";
            ExpectedHashOfOnetoNine = "F720446C9BFDC8479D9FA53BC8B9144FC3FE42ED";
            ExpectedHashOfabcde = "14F45FAC4BE0302E740CCC6FE99D75A6CAB0E177";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "89CFB85851EA674DF045CDDE4BAC3C3037E01BDE";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "DDEE30DCE9CD2A11C38ADA8AC94FD5BD90EC1BA4";
        }
    }

    [TestClass]
    public class Tiger2_3_192Tests : CryptoHashBaseTests
    {
        public Tiger2_3_192Tests()
        {
            hash = HashFactory.Crypto.CreateTiger2_3_192();

            ExpectedHashOfEmptyData = "4441BE75F6018773C206C22745374B924AA8313FEF919F41";
            ExpectedHashOfDefaultData = "DEB1924D290E3D5567792A8171BFC44F70B5CD13480D6D5C";
            ExpectedHashOfOnetoNine = "82FAF69673762B9FD8A0C902BDB395C12B0CBDDC66957838";
            ExpectedHashOfabcde = "E1F0DAC9E852ECF1270FB691C35506D4BEDB12A09D6BF911";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "8540FF4EBA4C823EEC5EDC244D83B93381B75CE92F753005";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "C70FA522EACE7D870F914A086BD1D9807A6FDC405C5A09DB";
        }
    }

    [TestClass]
    public class Tiger2_4_192Tests : CryptoHashBaseTests
    {
        public Tiger2_4_192Tests()
        {
            hash = HashFactory.Crypto.CreateTiger2_4_192();

            ExpectedHashOfEmptyData = "6A7201A47AAC2065913811175553489ADD0F8B99E65A0955";
            ExpectedHashOfDefaultData = "22EE5BFE174B8C1C23361306C3E8F32C92075577F9115C2A";
            ExpectedHashOfOnetoNine = "75B7D71ACD40FE5B5D3263C1F68F4CF5A5DA963B39413ACA";
            ExpectedHashOfabcde = "9FBB0FBF818C0302890CE373559D23702D87C69B9D1B29D5";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "0B3BB091C80889FB2E65FCA6ADCEC87147311F242AEC5519";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "3B182344C171E8843B3D30887274FC7248A7CCD49AA84E77";
        }
    }

    [TestClass]
    public class Tiger2_5_192Tests : CryptoHashBaseTests
    {
        public Tiger2_5_192Tests()
        {
            hash = HashFactory.Crypto.CreateTiger2_5_192();

            ExpectedHashOfEmptyData = "61C657CC0C3C147ED90779B36A1E811F1D27F406E3F37010";
            ExpectedHashOfDefaultData = "7F71F95B346733E7022D4B85BDA9C51E904825F73AF0E8AE";
            ExpectedHashOfOnetoNine = "F720446C9BFDC8479D9FA53BC8B9144FC3FE42ED1440C213";
            ExpectedHashOfabcde = "14F45FAC4BE0302E740CCC6FE99D75A6CAB0E177B4ADF2A8";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "C583EDE2D12E49F48BD29642C69D4470016293F47374339F";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "19AD11BA8D3534C41CAA2A9DAA80958EDCDB0B67FF3BF55D";
        }
    }
}