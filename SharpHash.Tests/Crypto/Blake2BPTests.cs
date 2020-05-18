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
    public class Blake2BPTests : BlakeBaseTests
    {
        public Blake2BPTests()
        {
            Int32 LIdx;

            byte[] LKey = new byte[64];

            for (LIdx = 0; LIdx < LKey.Length; LIdx++)
                LKey[LIdx] = (byte)LIdx;

            hash = HashFactory.Crypto.CreateBlake2BP(64, null);

            HashInstanceWithKey = HashFactory.Crypto.CreateBlake2BP(64, LKey);

            ExpectedHashOfEmptyData = "B5EF811A8038F70B628FA8B294DAAE7492B1EBE343A80EAABBF1F6AE664DD67B9D90B0120791EAB81DC96985F28849F6A305186A85501B405114BFA678DF9380";
            ExpectedHashOfDefaultData = "6F02764BDBA4184E50CAA52539BC392239D31E1BC76CEACBCA42630BCB7B48B527F65AA2F50363C0E26A287B758C87BC77C7175AB7A12B33104330F5A1C6E171";
            ExpectedHashOfOnetoNine = "E70843E71EF73EF84D991990687CB72E272E590F7E86F491935E9904F0582A165A388F956D691101C5D2B035634E4415C3CB21D7F721702CC64791D53AEDB9E2";
            ExpectedHashOfabcde = "C96CA7B60257D18A67EC6DAF4E06A6A0F882ECEE22605DBE64DFAD2D7AA2FF939726385C7E60F00A2A38CF302E460C33EAE769CA5652FA8456EA6A75DC6AAC39";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "62B264D5D5DFC01350B69C083B239426EC8A8F971FAC8DCB0B6A4825DD664CB992413AA1F7E5D2950BFFB9C207A9B084591633A96F3F590A861B27C3B827D3BC";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "671A8EE18AD7BCC940CF4B35B47D0AAA89077AA8503E4E374A5BC2803758BBF04C6C80F97E5B71CD79A1E6DCD6585EB82A5F5482DB268B462D651530CE5CB177";

            UnkeyedTestVectors = Blake2BPTestVectors.UnkeyedBlake2BP;
            KeyedTestVectors = Blake2BPTestVectors.KeyedBlake2BP;
        }

    }
}