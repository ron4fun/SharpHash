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
    public class Snefru_8_128Tests : CryptoHashBaseTests
    {
        public Snefru_8_128Tests()
        {
            hash = HashFactory.Crypto.CreateSnefru_8_128();

            ExpectedHashOfEmptyData = "8617F366566A011837F4FB4BA5BEDEA2";
            ExpectedHashOfDefaultData = "1EA32485C121D07D1BD22FC4EDCF554F";
            ExpectedHashOfOnetoNine = "486D27B1F5F4A20DEE14CC466EDA9069";
            ExpectedHashOfabcde = "ADD78FA0BEA8F6283FE5D011BE6BCA3B";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "296DEC851C9F6A6C9E1FD42679CE3FD2";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "B7D06604FCA943939525BA82BA69706E";
        }
    }
}