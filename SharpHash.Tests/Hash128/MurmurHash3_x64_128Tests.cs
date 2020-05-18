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
    public class MurmurHash3_x64_128Tests : HashWithUInt32AsKeyBaseTests
    {
        public MurmurHash3_x64_128Tests()
        {
            hash = HashFactory.Hash128.CreateMurmurHash3_x64_128();

            ExpectedHashOfEmptyData = "00000000000000000000000000000000";
            ExpectedHashOfDefaultData = "705BD3C954B94BE056F06B68662E6364";
            ExpectedHashOfRandomString = "D30654ABBD8227E367D73523F0079673";
            ExpectedHashOfZerotoFour = "0F04E459497F3FC1ECCC6223A28DD613";
            ExpectedHashOfEmptyDataWithOneAsKey = "4610ABE56EFF5CB551622DAA78F83583";
            ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "ADFD14988FB1F8582A1B67C1BBACC218";
        }
    }
}