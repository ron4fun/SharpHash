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
    public class Keccak_224Tests : CryptoHashBaseTests
    {
        public Keccak_224Tests()
        {
            hash = HashFactory.Crypto.CreateKeccak_224();

            ExpectedHashOfEmptyData = "F71837502BA8E10837BDD8D365ADB85591895602FC552B48B7390ABD";
            ExpectedHashOfDefaultData = "1BA678212F840E95F076B4E3E75310D4DA4308E04396E07EF1683ACE";
            ExpectedHashOfOnetoNine = "06471DE6C635A88E7470284B2C2EBF9BD7E5E888CBBD128C21CB8308";
            ExpectedHashOfabcde = "16F91F7E036DF526340440C34C231862D8F6319772B670EEFD4703FF";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "8C500F95CB013CBC16DEB6CB742D470E20404E0A1776647EAAB6E869";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "D6CE783743A36717F893DFF82DE89633F21089AFBE4F26431E269650";
        }
    }
}