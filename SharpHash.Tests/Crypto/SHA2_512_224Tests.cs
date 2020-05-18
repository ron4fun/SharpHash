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
    public class SHA2_512_224Tests : CryptoHashBaseTests
    {
        public SHA2_512_224Tests()
        {
            hash = HashFactory.Crypto.CreateSHA2_512_224();

            ExpectedHashOfEmptyData = "6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4";
            ExpectedHashOfDefaultData = "7A95749FB7F4489A45275556F5D905D28E1B637DCDD6537336AB6234";
            ExpectedHashOfOnetoNine = "F2A68A474BCBEA375E9FC62EAAB7B81FEFBDA64BB1C72D72E7C27314";
            ExpectedHashOfabcde = "880E79BB0A1D2C9B7528D851EDB6B8342C58C831DE98123B432A4515";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "B932866547894977F6E4C61D137FFC2508C639BA6786F45AC64731C8";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "9BC318A84B90F7FF55C53E3F4B602EAD13BB579EB1794455B29562B4";
        }
    }
}