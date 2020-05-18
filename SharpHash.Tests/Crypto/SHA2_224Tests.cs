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
    public class SHA2_224Tests : CryptoHashBaseTests
    {
        public SHA2_224Tests()
        {
            hash = HashFactory.Crypto.CreateSHA2_224();

            ExpectedHashOfEmptyData = "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F";
            ExpectedHashOfDefaultData = "DF2B86ED008508F542443C4B1810AA5A0F5658692B808EEB1D0A2F7E";
            ExpectedHashOfOnetoNine = "9B3E61BF29F17C75572FAE2E86E17809A4513D07C8A18152ACF34521";
            ExpectedHashOfabcde = "BDD03D560993E675516BA5A50638B6531AC2AC3D5847C61916CFCED6";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "86855E59D8B09A3C7632D4E176C4B65C549255F417FEF9EEF2D4167D";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "EC47E83DB5DD735EBB7AA4A898460950B16A3A0FA48E4BB9184EA3D1";
        }
    }
}