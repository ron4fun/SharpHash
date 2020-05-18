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
    public class WhirlPoolTests : CryptoHashBaseTests
    {
        public WhirlPoolTests()
        {
            hash = HashFactory.Crypto.CreateWhirlPool();

            ExpectedHashOfEmptyData = "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3";
            ExpectedHashOfDefaultData = "9D2BB47D6F6D9F0DBAF08BEF416DE06C98CDF293F3D1AD2422A63A9ADFBD9AA33F888A1C6FE7C16DF33B2BD9FFD8EF160BCF6AB4F21B682DC238A3BE03AB0F12";
            ExpectedHashOfOnetoNine = "21D5CB651222C347EA1284C0ACF162000B4D3E34766F0D00312E3480F633088822809B6A54BA7EDFA17E8FCB5713F8912EE3A218DD98D88C38BBF611B1B1ED2B";
            ExpectedHashOfabcde = "5D745E26CCB20FE655D39C9E7F69455758FBAE541CB892B3581E4869244AB35B4FD6078F5D28B1F1A217452A67D9801033D92724A221255A5E377FE9E9E5F0B2";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "A2CF231E2E01B310A91A7BF92435AE0258997AB969D0B2E09378C0F30C73E4434894A836B3F580683F58FC56DA87C685927AE0FC80D2548A35CD3C7528A83AC1";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "72B3CFC10CC32F9203670984407594B9F2A6C9F1A46C3FF7DF76AD07207758F96CF46C448A7687EBBA5EBC046984B4837320306EB27978A58B8CF447978CADEA";
        }
    }
}