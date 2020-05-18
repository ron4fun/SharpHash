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
    public class RIPEMD128Tests : CryptoHashBaseTests
    {
        public RIPEMD128Tests()
        {
            hash = HashFactory.Crypto.CreateRIPEMD128();

            ExpectedHashOfEmptyData = "CDF26213A150DC3ECB610F18F6B38B46";
            ExpectedHashOfDefaultData = "75891B00B2874EDCAF7002CA98264193";
            ExpectedHashOfOnetoNine = "1886DB8ACDCBFEAB1E7EE3780400536F";
            ExpectedHashOfabcde = "A0A954BE2A779BFB2129B72110C5782D";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "E93930A64EF6807C4D80EF30DF86AFA7";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "BA844D13A1215E20634A49D5599197EF";
        }
    }
}