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
    public class GostTests : CryptoHashBaseTests
    {
        public GostTests()
        {
            hash = HashFactory.Crypto.CreateGost();

            ExpectedHashOfEmptyData = "CE85B99CC46752FFFEE35CAB9A7B0278ABB4C2D2055CFF685AF4912C49490F8D";
            ExpectedHashOfDefaultData = "21DCCFBF20D313170333BA15596338FB5964267328EB42CA10E269B7045FF856";
            ExpectedHashOfOnetoNine = "264B4E433DEE474AEC465FA9C725FE963BC4B4ABC4FDAC63B7F73B671663AFC9";
            ExpectedHashOfabcde = "B18CFD04F92DC1D83325036BC723D36DB25EDE41AE879D2545FC7F377B700899";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "DE9D68F7793C829E7369AC09493A7749B2637A7B1D572A70549936E09F2D1D82";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "6E4E2895E194BEB0A083B1DED6C4084F5E7F37BAAB988D288D9707235F2F8294";
        }
    }
}