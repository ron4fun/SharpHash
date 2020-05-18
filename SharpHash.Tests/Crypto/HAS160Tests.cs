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
    public class HAS160Tests : CryptoHashBaseTests
    {
        public HAS160Tests()
        {
            hash = HashFactory.Crypto.CreateHAS160();

            ExpectedHashOfEmptyData = "307964EF34151D37C8047ADEC7AB50F4FF89762D";
            ExpectedHashOfDefaultData = "2773EDAC4501514254D7B1DF091D6B7652250A52";
            ExpectedHashOfOnetoNine = "A0DA48CCD36C9D24AA630D4B3673525E9109A83C";
            ExpectedHashOfabcde = "EEEA94C2F0450B639BC2ACCAF4AEB172A5885313";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "7D2F0051F2BD817A4C27F126882353BCD300B7CA";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "53970A7AC510A85D0E22FF506FED5B57188A8B3F";
        }
    }
}