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
    public class GOST3411_2012_512Tests : HashBaseTests
    {
        private string ExpectedHashOfQuickBrownFox { get; set; }

        public GOST3411_2012_512Tests()
        {
            hash = HashFactory.Crypto.CreateGOST3411_2012_512();

            ExpectedHashOfEmptyData = "8E945DA209AA869F0455928529BCAE4679E9873AB707B55315F56CEB98BEF0A7362F715528356EE83CDA5F2AAC4C6AD2BA3A715C1BCD81CB8E9F90BF4C1C1A8A";
            ExpectedHashOfQuickBrownFox = "D2B793A0BB6CB5904828B5B6DCFB443BB8F33EFC06AD09368878AE4CDC8245B97E60802469BED1E7C21A64FF0B179A6A1E0BB74D92965450A0ADAB69162C00FE";
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
            TestHelper.TestHMACCloneIsCorrect(hash.Clone());
        }
    }
}