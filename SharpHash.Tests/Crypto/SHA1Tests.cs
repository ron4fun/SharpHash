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
    public class SHA1Tests : CryptoHashBaseTests
    {
        public SHA1Tests()
        {
            hash = HashFactory.Crypto.CreateSHA1();

            ExpectedHashOfEmptyData = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
            ExpectedHashOfDefaultData = "C8389876E94C043C47BA4BFF3D359884071DC310";
            ExpectedHashOfOnetoNine = "F7C3BC1D808E04732ADF679965CCC34CA7AE3441";
            ExpectedHashOfabcde = "03DE6C570BFE24BFC328CCD7CA46B76EADAF4334";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "E70699720F4222E3A4A4474F14F13CBC3316D9B2";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "CD409025AA5F34ABDC660856463155B23C89B16A";
        }
    }
}