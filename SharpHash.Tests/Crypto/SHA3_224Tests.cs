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
    public class SHA3_224Tests : CryptoHashBaseTests
    {
        public SHA3_224Tests()
        {
            hash = HashFactory.Crypto.CreateSHA3_224();

            ExpectedHashOfEmptyData = "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7";
            ExpectedHashOfDefaultData = "1D2BDFB95B0203C2BB7C739D813D69521EC7A3047E3FCA15CD305C95";
            ExpectedHashOfOnetoNine = "5795C3D628FD638C9835A4C79A55809F265068C88729A1A3FCDF8522";
            ExpectedHashOfabcde = "6ACFAAB70AFD8439CEA3616B41088BD81C939B272548F6409CF30E57";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "38FABCD5E29DE7AD7429BD9124F804FFD340D7B9F77A83DC25EC53B8";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "DA17722BA1E4BD728A83015A83430A67577F283A0EFCB457C327A980";
        }
    }
}