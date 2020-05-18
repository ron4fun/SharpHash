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
    public class PanamaTests : CryptoHashBaseTests
    {
        public PanamaTests()
        {
            hash = HashFactory.Crypto.CreatePanama();

            ExpectedHashOfEmptyData = "AA0CC954D757D7AC7779CA3342334CA471ABD47D5952AC91ED837ECD5B16922B";
            ExpectedHashOfDefaultData = "69A05A5A5DDB32F5589257458BBDD059FB30C4486C052D81029DDB2864E90813";
            ExpectedHashOfOnetoNine = "3C83D2C9109DE4D1FA64833683A7C280591A7CFD8516769EA879E56A4AD39B99";
            ExpectedHashOfabcde = "B064E5476A3F511105B75305FC2EC31578A6B200FB5084CF937C179F1C52A891";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "93226A060B4A82D1D9FBEE6B78424F8E3E871BE7DA77A9D17D5C78D5F415E631";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "3C15C9B7CDC77470BC02CA96711B66FAA976AC2044F6F177ABCA93B1442EA376";
        }
    }
}