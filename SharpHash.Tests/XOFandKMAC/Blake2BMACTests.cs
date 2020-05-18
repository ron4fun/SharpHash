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
using SharpHash.Utils;
using System;
using System.Linq;
using System.Text;

namespace SharpHash.XOFandKMAC.Tests
{
    [TestClass]
    public class Blake2BMACTests
    {
        private void DoComputeBlake2BMAC(string a_Key, string a_Personalisation, string a_Salt, string a_Data,
            string a_ExpectedResult, Int32 a_OutputSizeInBits)
        {
            IHash LHash, LClone;
            Int32 LIdx;
            byte[] ActualResult, ActualResultClone, Key, Salt, Personalisation, Data;

            Key = Converters.ConvertHexStringToBytes(a_Key);
            Personalisation = Converters.ConvertStringToBytes(a_Personalisation, Encoding.UTF8);

            // if personalisation length != 16, resize to 16, padding with zeros if necessary
            if (Personalisation.Length != 16)
                Array.Resize(ref Personalisation, 16);

            Salt = Converters.ConvertHexStringToBytes(a_Salt);
            Data = Converters.ConvertStringToBytes(a_Data, Encoding.UTF8);

            LHash = HashFactory.Blake2BMAC.CreateBlake2BMAC(Key, Salt, Personalisation, a_OutputSizeInBits);

            LHash.Initialize();

            for (LIdx = 0; LIdx < Data.Length; LIdx++)
                LHash.TransformBytes(new byte[] { Data[LIdx] }); // do incremental hashing

            LClone = LHash.Clone();

            ActualResult = LHash.TransformFinal().GetBytes();
            ActualResultClone = LClone.TransformFinal().GetBytes();

            Assert.AreEqual(a_ExpectedResult,
                Converters.ConvertBytesToHexString(ActualResult, false),
                String.Format("Expected {0} But got {1}", a_ExpectedResult,
                Converters.ConvertBytesToHexString(ActualResult, false)));

            if (!ActualResult.SequenceEqual(ActualResultClone))
            {
                Assert.Fail(String.Format(
                    "Blake2BMAC mismatch on test vector against a clone, Expected \"{0}\" but got \"{1}\"",
                    a_ExpectedResult, Converters.ConvertBytesToHexString(ActualResultClone, false)));
            }

        } // end function DoComputeKMAC128

        [TestMethod]
        public void TestBlake2BMACSample1()
        {
            DoComputeBlake2BMAC("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "", "",
                "Sample input for outlen<digest_length", "2A", 1 * 8);
        }

        [TestMethod]
        public void TestBlake2BMACSample2()
        {
            DoComputeBlake2BMAC("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "application", "000102030405060708090A0B0C0D0E0F", "Combo input with outlen, custom and salt",
                "51742FC491171EAF6B9459C8B93A44BBF8F44A0B4869A17FA178C8209918AD96", 32 * 8);
        }

        [TestMethod]
        public void TestBlake2BMACSample3()
        {
            DoComputeBlake2BMAC("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "application", "000102030405060708090A0B0C0D0E0F", "Sample input for keylen<blocklen, salt and custom",
                "233A6C732212F4813EC4C9F357E35297E59A652FD24155205F00363F7C54734EE1E8C7329D92116CBEC62DB35EBB5D51F9E5C2BA41789B84AC9EBC266918E524",
                64 * 8);
        }

    }
}