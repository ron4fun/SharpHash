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
    public class SHA2_512_256Tests : CryptoHashBaseTests
    {
        public SHA2_512_256Tests()
        {
            hash = HashFactory.Crypto.CreateSHA2_512_256();

            ExpectedHashOfEmptyData = "C672B8D1EF56ED28AB87C3622C5114069BDD3AD7B8F9737498D0C01ECEF0967A";
            ExpectedHashOfDefaultData = "E1792BAAAEBFC58E213D0BA628BF2FF22CBA10526075702F7C1727B76BEB107B";
            ExpectedHashOfOnetoNine = "1877345237853A31AD79E14C1FCB0DDCD3DF9973B61AF7F906E4B4D052CC9416";
            ExpectedHashOfabcde = "DE8322B46E78B67D4431997070703E9764E03A1237B896FD8B379ED4576E8363";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "5EF407B913662BE3D98F5DA20D55C2A45D3F3E4FF771B2C2A482E35F6A757E71";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "1467239C9D47E1962905D03D7006170A04D05E4508BB47E30AD9481FBDA975FF";
        }
    }
}