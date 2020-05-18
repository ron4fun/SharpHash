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
    public class Keccak_384Tests : CryptoHashBaseTests
    {
        public Keccak_384Tests()
        {
            hash = HashFactory.Crypto.CreateKeccak_384();

            ExpectedHashOfEmptyData = "2C23146A63A29ACF99E73B88F8C24EAA7DC60AA771780CCC006AFBFA8FE2479B2DD2B21362337441AC12B515911957FF";
            ExpectedHashOfDefaultData = "6A53977DFA0BCDCF069635CF541AB64C7E41923FCB3A5B049AB98878411D0E71DF95FCAB0072F1AE8B931BF4490B823E";
            ExpectedHashOfOnetoNine = "EFCCAE72CE14656C434751CF737E70A57AB8DD2C76F5ABE01E52770AFFD77B66D2B80977724A00A6D971B702906F8032";
            ExpectedHashOfabcde = "6E577A02A783232ACF34841399883F5F69D9AC78F48C7F4431CBC4F669C2A0F1CA3B1BECB7701B8315588D64D6C3746A";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "A7740E29EEF80306DA09D7AF0868E925D6144996F99A01F973F03C4BD85D1EC20567936CA34A443B62A890AD8D263D2A";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "044628643016E3EA30DE6CA3A8A1276F6BF1A5443CEF96BAA73199CF64FFC52D7F38254C671DB2933FFC8DD3E5B77223";
        }
    }
}