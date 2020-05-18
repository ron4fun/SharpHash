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
    public class Grindahl256Tests : CryptoHashBaseTests
    {
        public Grindahl256Tests()
        {
            hash = HashFactory.Crypto.CreateGrindahl256();

            ExpectedHashOfEmptyData = "45A7600159AF54AE110FCB6EA0F38AD57875EAC814F74D2CBC247D28C89923E6";
            ExpectedHashOfDefaultData = "AC72E90B0F3F5864A0AF3C43E2A73E393DEBF22AB81B6786ADE22B4517DAAAB6";
            ExpectedHashOfOnetoNine = "D2460846C5FE9E4750985CC9244D2458BEFD884435121FE56528022A3C7605B7";
            ExpectedHashOfabcde = "5CDA73422F36E41087795BB6C21D577BAAF114E4A6CCF33D919E700EE2489FE2";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "02D964EE346B0C333CEC0F5D7E68C5CFAAC1E3CB0C06FE36418E17AA3AFCA2BE";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "65BA6F8EFA5B566D556EC8E3A2EC67DB7EE9BDEE663F17A8B8E7FAD067481023";
        }
    }
}