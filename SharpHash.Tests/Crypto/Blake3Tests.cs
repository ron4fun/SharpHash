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
    public class Blake3Tests : CryptoHashBaseTests
    {
        public Blake3Tests()
        {
            hash = HashFactory.Crypto.CreateBlake3_256(null);

            ExpectedHashOfEmptyData = "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262";
            ExpectedHashOfDefaultData = "BB8DB7E4155BFDB254AD49D8D3105C57B6AC3E783E6D316A75E8B8F8911EB41F";
            ExpectedHashOfOnetoNine = "B7D65B48420D1033CB2595293263B6F72EABEE20D55E699D0DF1973B3C9DEED1";
            ExpectedHashOfabcde = "0648C03B5AD9BB6DDF8306EEF6A33EBAE8F89CB4741150C1AE9CD662FDCC1EE2";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "A7F72F6A236F4572079427B0FD44516705B3322FB3A8D85ACFCB759804529E96";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "D4DE3C2DE89625AF7076FEC6CFD7B0D318665514D1F88CF68F567AC4971B6681";
        }
    }
}