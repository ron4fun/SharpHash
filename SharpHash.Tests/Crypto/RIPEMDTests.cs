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
    public class RIPEMDTests : CryptoHashBaseTests
    {
        public RIPEMDTests()
        {
            hash = HashFactory.Crypto.CreateRIPEMD();

            ExpectedHashOfEmptyData = "9F73AA9B372A9DACFB86A6108852E2D9";
            ExpectedHashOfDefaultData = "B3F629A9786744AA105A2C150869C236";
            ExpectedHashOfOnetoNine = "C905B44C6429AD0A1934550037D4816F";
            ExpectedHashOfabcde = "68D2362617E85CF1BF7381DF14045DBB";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "B06D09CE5452ADEEADF468E00DAC5C8B";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "219ACFCF07BDB775FBA73DACE1E97E08";
        }
    }
}