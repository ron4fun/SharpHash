///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019 - 2020  Mbadiwe Nnaemeka Ronald
/// Github Repository <https://github.com/ron4fun/SharpHash>
///
/// The contents of this file are subject to the
/// Mozilla Public License Version 2.0 (the "License");
/// you may not use this file except in
/// compliance with the License. You may obtain a copy of the License
/// at https://www.mozilla.org/en-US/MPL/2.0/
///
/// Software distributed under the License is distributed on an "AS IS"
/// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
/// the License for the specific language governing rights and
/// limitations under the License.
///
/// Acknowledgements:
///
/// Thanks to Ugochukwu Mmaduekwe (https://github.com/Xor-el) for his creative
/// development of this library in Pascal/Delphi (https://github.com/Xor-el/HashLib4Pascal).
///
/// Also, I will like to thank Udezue Chukwunwike (https://github.com/IzarchTech) for
/// his contributions to the growth and development of this library.
///
////////////////////////////////////////////////////////////////////////

using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Tiger_3_128Tests : CryptoHashBaseTests
    {
        public Tiger_3_128Tests()
        {
            hash = HashFactory.Crypto.CreateTiger_3_128();

            ExpectedHashOfEmptyData = "3293AC630C13F0245F92BBB1766E1616";
            ExpectedHashOfDefaultData = "C76C85CE853F6E9858B507DA64E33DA2";
            ExpectedHashOfOnetoNine = "0672665140A491BB35040AA9943D769A";
            ExpectedHashOfabcde = "BFD4041233531F1EF1E9A66D7A0CEF76";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "331B89BDEC8B418091A883C139B3F858";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "0FA849F65841F2E621E2C882BE7CF80F";
        }
    }

    [TestClass]
    public class Tiger_4_128Tests : CryptoHashBaseTests
    {
        public Tiger_4_128Tests()
        {
            hash = HashFactory.Crypto.CreateTiger_4_128();

            ExpectedHashOfEmptyData = "24CC78A7F6FF3546E7984E59695CA13D";
            ExpectedHashOfDefaultData = "42CAAEB3A7218E379A78E4F1F7FBADA4";
            ExpectedHashOfOnetoNine = "D9902D13011BD217DE965A3BA709F5CE";
            ExpectedHashOfabcde = "7FD0E2FAEC50261EF48D3B87C554EE73";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "5365F31B5077249CA8C0C11FB29E06C1";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "856B697CEB606B1DF42B475D0C5587B5";
        }
    }

    [TestClass]
    public class Tiger_5_128Tests : CryptoHashBaseTests
    {
        public Tiger_5_128Tests()
        {
            hash = HashFactory.Crypto.CreateTiger_5_128();

            ExpectedHashOfEmptyData = "E765EBE4C351724A1B99F96F2D7E62C9";
            ExpectedHashOfDefaultData = "D6B8DCEA252160A4CBBF6A57DA9ABA78";
            ExpectedHashOfOnetoNine = "BCCCB6421B3EC291A062A33DFF21BA76";
            ExpectedHashOfabcde = "1AB49D19F3C93B6FF4AB536951E5A6D0";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "67B3B43D5CE62BE8B54805E315576F06";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "49D450EC293D5565CE82284FA52FDC51";
        }
    }

    [TestClass]
    public class Tiger_3_160Tests : CryptoHashBaseTests
    {
        public Tiger_3_160Tests()
        {
            hash = HashFactory.Crypto.CreateTiger_3_160();

            ExpectedHashOfEmptyData = "3293AC630C13F0245F92BBB1766E16167A4E5849";
            ExpectedHashOfDefaultData = "C76C85CE853F6E9858B507DA64E33DA27DE49F86";
            ExpectedHashOfOnetoNine = "0672665140A491BB35040AA9943D769A47BE83FE";
            ExpectedHashOfabcde = "BFD4041233531F1EF1E9A66D7A0CEF76A3E0FE75";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "6C256489CD5E62C9B9F236523B030A56CCDF5A8C";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "45AF6513756EB15B9504CE8212F3D43AE739E470";
        }
    }

    [TestClass]
    public class Tiger_4_160Tests : CryptoHashBaseTests
    {
        public Tiger_4_160Tests()
        {
            hash = HashFactory.Crypto.CreateTiger_4_160();

            ExpectedHashOfEmptyData = "24CC78A7F6FF3546E7984E59695CA13D804E0B68";
            ExpectedHashOfDefaultData = "42CAAEB3A7218E379A78E4F1F7FBADA432E1D4B6";
            ExpectedHashOfOnetoNine = "D9902D13011BD217DE965A3BA709F5CE7E75ED2C";
            ExpectedHashOfabcde = "7FD0E2FAEC50261EF48D3B87C554EE739E8FBD98";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "FE4F2273571AD900BB6A2935AD9E4E53DE98B24B";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "E8E8B8EF52CF7866A4E0AEAE7DE79878D5564997";
        }
    }

    [TestClass]
    public class Tiger_5_160Tests : CryptoHashBaseTests
    {
        public Tiger_5_160Tests()
        {
            hash = HashFactory.Crypto.CreateTiger_5_160();

            ExpectedHashOfEmptyData = "E765EBE4C351724A1B99F96F2D7E62C9AACBE64C";
            ExpectedHashOfDefaultData = "D6B8DCEA252160A4CBBF6A57DA9ABA78E4564864";
            ExpectedHashOfOnetoNine = "BCCCB6421B3EC291A062A33DFF21BA764596C58E";
            ExpectedHashOfabcde = "1AB49D19F3C93B6FF4AB536951E5A6D05EF6394C";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "5ACE8DB66A68836ADAC0BD563D43C01E82181E32";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "5F403B5F7F9A341545F55265698DD77DB8D3D6D4";
        }
    }

    [TestClass]
    public class Tiger_3_192Tests : CryptoHashBaseTests
    {
        public Tiger_3_192Tests()
        {
            hash = HashFactory.Crypto.CreateTiger_3_192();

            ExpectedHashOfEmptyData = "3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3";
            ExpectedHashOfDefaultData = "C76C85CE853F6E9858B507DA64E33DA27DE49F8601F6A830";
            ExpectedHashOfOnetoNine = "0672665140A491BB35040AA9943D769A47BE83FEF2126E50";
            ExpectedHashOfabcde = "BFD4041233531F1EF1E9A66D7A0CEF76A3E0FE756B36A7D7";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "E46789FA64BFEE51EE17C7D257B6DF892A39FA9A7BC65CF9";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "9B53DDED2647666E9C31CF0F93B3B83E9FF64DF4532F3DDC";
        }
    }

    [TestClass]
    public class Tiger_4_192Tests : CryptoHashBaseTests
    {
        public Tiger_4_192Tests()
        {
            hash = HashFactory.Crypto.CreateTiger_4_192();

            ExpectedHashOfEmptyData = "24CC78A7F6FF3546E7984E59695CA13D804E0B686E255194";
            ExpectedHashOfDefaultData = "42CAAEB3A7218E379A78E4F1F7FBADA432E1D4B6A41827B0";
            ExpectedHashOfOnetoNine = "D9902D13011BD217DE965A3BA709F5CE7E75ED2CB791FEA6";
            ExpectedHashOfabcde = "7FD0E2FAEC50261EF48D3B87C554EE739E8FBD98F9A0B332";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "31C5440140BD657ECEBA5172E7853E526290060C1A6335D1";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "D1113A9110545D0F3C97BE1451A8FAED205B1F27B3D74560";
        }
    }

    [TestClass]
    public class Tiger_5_192Tests : CryptoHashBaseTests
    {
        public Tiger_5_192Tests()
        {
            hash = HashFactory.Crypto.CreateTiger_5_192();

            ExpectedHashOfEmptyData = "E765EBE4C351724A1B99F96F2D7E62C9AACBE64C63B5BCA2";
            ExpectedHashOfDefaultData = "D6B8DCEA252160A4CBBF6A57DA9ABA78E45648645715E3CE";
            ExpectedHashOfOnetoNine = "BCCCB6421B3EC291A062A33DFF21BA764596C58E30854A92";
            ExpectedHashOfabcde = "1AB49D19F3C93B6FF4AB536951E5A6D05EF6394C3471A08F";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "C8A09D6DB257C85B99051F3BC410F56C4D92EEBA311005DC";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "8D56E7164C246EAF4708AAEECFE4DD439F5B4396A54049A6";
        }
    }
}