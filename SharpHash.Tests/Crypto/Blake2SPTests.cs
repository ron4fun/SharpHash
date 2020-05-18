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
using System;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Blake2SPTests : BlakeBaseTests
    {
        public Blake2SPTests()
        {
            Int32 LIdx;

            byte[] LKey = new byte[32];

            for (LIdx = 0; LIdx < LKey.Length; LIdx++)
                LKey[LIdx] = (byte)LIdx;

            hash = HashFactory.Crypto.CreateBlake2SP(32, null);

            HashInstanceWithKey = HashFactory.Crypto.CreateBlake2SP(32, LKey);

            ExpectedHashOfEmptyData = "DD0E891776933F43C7D032B08A917E25741F8AA9A12C12E1CAC8801500F2CA4F";
            ExpectedHashOfDefaultData = "F1617895134C203ED0A9C8CC72938161EBC9AB6F233BBD3CCFC4D4BCA08A5ED0";
            ExpectedHashOfOnetoNine = "D6D3157BD4E809982E0EEA22C5AF5CDDF05473F6ECBE353119591E6CDCB7127E";
            ExpectedHashOfabcde = "107EEF69D795B14C8411EEBEFA897429682108397680377C78E5D214F014916F";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "7E061EC8E97D200F21BD7DB59FF4ED7BB1F7327D9E75EB3D922B926A76FEFE3F";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "D818A87A70949BDA7DE9765650D665C49B1B5CF11B05A1780901C46A91FFD786";

            UnkeyedTestVectors = Blake2SPTestVectors.UnkeyedBlake2SP;
            KeyedTestVectors = Blake2SPTestVectors.KeyedBlake2SP;
        }

    }
}