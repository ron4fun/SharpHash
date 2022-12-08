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
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System;
using System.Text;

namespace SharpHash.Hash64.Tests
{
    [TestClass]
    public class SipHash128_2_4Tests : HashAdapter1BaseTests
    {
        private string HashOfDefaultDataWithSixteenByteKey { get; set; }

        public SipHash128_2_4Tests()
        {
            hash = HashFactory.Hash128.CreateSipHash128_2_4();

            ExpectedHashOfEmptyData = "A3817F04BA25A8E66DF67214C7550293";
            ExpectedHashOfDefaultData = "312C82F65D5A567B333CD772F045E36C";
            ExpectedHashOfOnetoNine = "CE94828373303D1AB5FC781744AD71CE";
            ExpectedHashOfabcde = "EB8662A95F0D718811E7CEDBDF03541C";
            HashOfDefaultDataWithSixteenByteKey = "312C82F65D5A567B333CD772F045E36C";
        }

        [TestMethod]
        public void TestZeroToFifteenInHex()
        {
            IHashWithKey LIHashWithKey;

            string ExpectedString = HashOfDefaultDataWithSixteenByteKey;
            LIHashWithKey = (hash as IHashWithKey);
            LIHashWithKey.Key = Converters.ConvertHexStringToBytes(TestConstants.ZeroToFifteenInHex);

            string ActualString = LIHashWithKey.ComputeString(TestConstants.DefaultData,
                Encoding.UTF8).ToString();

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.",
                ExpectedString, ActualString));
        }
    }
}