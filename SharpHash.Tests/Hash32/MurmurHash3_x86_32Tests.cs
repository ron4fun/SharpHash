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
using SharpHash.Tests;

namespace SharpHash.Hash32.Tests
{
    [TestClass]
    public class MurmurHash3_x86_32Tests : HashWithUInt32AsKeyBaseTests
    {
        public MurmurHash3_x86_32Tests()
        {
            hash = HashFactory.Hash32.CreateMurmurHash3_x86_32();

            ExpectedHashOfEmptyData = "00000000";
            ExpectedHashOfDefaultData = "3D97B9EB";
            ExpectedHashOfRandomString = "A8D02B9A";
            ExpectedHashOfZerotoFour = "19D02170";
            ExpectedHashOfEmptyDataWithOneAsKey = "514E28B7";
            ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "B05606FE";
        }

        [TestMethod]
        new public void TestRandomString()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.RandomStringRecord,
                ExpectedHashOfRandomString, hash);
        }
    }
}