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
using System.Linq;
using System.Text;

namespace SharpHash.KDF.Tests
{
    [TestClass]
    public class PBKDF_Blake3TestCase
    {
        const string ctxString = "BLAKE3 2019-12-27 16:29:52 test vectors context";
        const Int32 ByteCount = 32;

        private byte[] Ctx { get; set; }
        private byte[] FullInput { get; set; }
        private IKDFNotBuiltIn KdfInstance { get; set; }

        public PBKDF_Blake3TestCase()
        {
            Ctx = Converters.ConvertStringToBytes(ctxString, Encoding.UTF8);
            FullInput = Enumerable.Range(0, 1 << 15).Select(i => (byte)(i % 251)).ToArray();            
            KdfInstance =
                HashFactory.KDF.PBKDF_Blake3.CreatePBKDF_Blake3(TestConstants.EmptyBytes, TestConstants.EmptyBytes);
        }
            
        [TestMethod]
        public void TestNullKeyThrowsCorrectException()
        {
            Assert.ThrowsException<ArgumentNullHashLibException>(()
                => HashFactory.KDF.PBKDF_Blake3.CreatePBKDF_Blake3(null, Ctx));
        }

        [TestMethod]
        public void TestNullContextThrowsCorrectException()
        {
            Assert.ThrowsException<ArgumentNullHashLibException>(()
                => HashFactory.KDF.PBKDF_Blake3.CreatePBKDF_Blake3(TestConstants.EmptyBytes, null));
        }

        [TestMethod]
        public void TestCheckTestVectors()
        {
            foreach (var vector in Blake3TestVectors.Blake3Vectors)
            {
                byte[] chunkedInput = new byte[Convert.ToInt32(vector[0])];
                Array.Copy(FullInput, chunkedInput, chunkedInput.Length);

                KdfInstance = HashFactory.KDF.PBKDF_Blake3.CreatePBKDF_Blake3(chunkedInput, Ctx);

                var output = KdfInstance.GetBytes(vector[3].Length >> 1);

                Assert.IsTrue(TestHelper.Compare(output, Converters.ConvertHexStringToBytes(vector[3])),
                    "test vector mismatch");
            } // end foreach
        }

    } //
}