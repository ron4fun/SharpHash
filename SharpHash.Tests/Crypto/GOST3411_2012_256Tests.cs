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

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class GOST3411_2012_256Tests : HashBaseTests
    {
        private string ExpectedHashOfQuickBrownFox { get; set; }

        public GOST3411_2012_256Tests()
        {
            hash = HashFactory.Crypto.CreateGOST3411_2012_256();

            ExpectedHashOfEmptyData = "3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB";
            ExpectedHashOfQuickBrownFox = "3E7DEA7F2384B6C5A3D0E24AAA29C05E89DDD762145030EC22C71A6DB8B2C1F4";
        }

        [TestMethod]
        public new void TestDefaultData() // For QuickBrownFox
        {
            TestHelper.TestActualAndExpectedData(TestConstants.QuickBrownDog,
            ExpectedHashOfQuickBrownFox, hash);
        }

        [TestMethod]
        public new void TestIncrementalHash()
        {
            TestHelper.TestIncrementalHash(TestConstants.QuickBrownDog,
            ExpectedHashOfQuickBrownFox, hash.Clone());
        }

        [TestMethod]
        public void TestHMACCloneIsCorrect()
        {
            TestHelper.TestHMACCloneIsCorrect(hash);
        }
    }
}