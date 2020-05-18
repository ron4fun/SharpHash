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

namespace SharpHash.Hash128.Tests
{
    [TestClass]
    public class MurmurHash3_x86_128Tests : HashWithUInt32AsKeyBaseTests
    {
        public MurmurHash3_x86_128Tests()
        {
            hash = HashFactory.Hash128.CreateMurmurHash3_x86_128();

            ExpectedHashOfEmptyData = "00000000000000000000000000000000";
            ExpectedHashOfDefaultData = "B35E1058738E067BF637B17075F14B8B";
            ExpectedHashOfRandomString = "9B5B7BA2EF3F7866889ADEAF00F3F98E";
            ExpectedHashOfZerotoFour = "35C5B3EE7B3B211600AE108800AE1088";
            ExpectedHashOfEmptyDataWithOneAsKey = "88C4ADEC54D201B954D201B954D201B9";
            ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "55315FA9E8129C7390C080B8FDB1C972";
        }
    }
}