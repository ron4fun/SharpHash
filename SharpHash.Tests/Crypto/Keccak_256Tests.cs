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
    public class Keccak_256Tests : CryptoHashBaseTests
    {
        public Keccak_256Tests()
        {
            hash = HashFactory.Crypto.CreateKeccak_256();

            ExpectedHashOfEmptyData = "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470";
            ExpectedHashOfDefaultData = "3FE42FE8CD6DAEF5ED7891846577F56AB35DC806424FC84A494C81E73BB06B5F";
            ExpectedHashOfOnetoNine = "2A359FEEB8E488A1AF2C03B908B3ED7990400555DB73E1421181D97CAC004D48";
            ExpectedHashOfabcde = "6377C7E66081CB65E473C1B95DB5195A27D04A7108B468890224BEDBE1A8A6EB";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "925FE69CEF38AA0D2CCBF6741ADD808F204CAA64EFA7E301A0A3EC332E40075E";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "1660234E7CCC29CFC8DEC8C6508AAF54EE48004EA9B56A15AC5742C89AAADA08";
        }
    }
}