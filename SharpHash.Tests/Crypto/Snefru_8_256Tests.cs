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
    public class Snefru_8_256Tests : CryptoHashBaseTests
    {
        public Snefru_8_256Tests()
        {
            hash = HashFactory.Crypto.CreateSnefru_8_256();

            ExpectedHashOfEmptyData = "8617F366566A011837F4FB4BA5BEDEA2B892F3ED8B894023D16AE344B2BE5881";
            ExpectedHashOfDefaultData = "230826DA59215F22AF36663491AECC4872F663722A5A7932428CB8196F7AF78D";
            ExpectedHashOfOnetoNine = "1C7DEDC33125AF7517970B97B635777FFBA8905D7A0B359776E3E683B115F992";
            ExpectedHashOfabcde = "8D2891FC6020D7DC93F7561C0CFDDE26426192B3E364A1F52B634482009DC8C8";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "EEE63DC493FCDAA2F826FFF81DB4BAC53CBBFD933BEA3B65C8BEBB576D921623";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "7E33D94C5A09B2E5F800417128BCF3EF2EDCB971884789A35AE4AA7F13A18147";
        }
    }
}