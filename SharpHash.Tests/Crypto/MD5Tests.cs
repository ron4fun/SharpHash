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
    public class MD5Tests : CryptoHashBaseTests
    {
        public MD5Tests()
        {
            hash = HashFactory.Crypto.CreateMD5();

            ExpectedHashOfEmptyData = "D41D8CD98F00B204E9800998ECF8427E";
            ExpectedHashOfDefaultData = "462EC1E50C8F2D5C387682E98F9BC842";
            ExpectedHashOfOnetoNine = "25F9E794323B453885F5181F1B624D0B";
            ExpectedHashOfabcde = "AB56B4D92B40713ACC5AF89985D4B786";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "696D0706C43816B551D874B9B3E4B7E6";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "09F705F43799213192622CCA6DF68941";
        }
    }
}