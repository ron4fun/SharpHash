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
using SharpHash.Interfaces;
using System;

namespace SharpHash
{
    [TestClass]
    public abstract class BlakeBaseTests : CryptoHashBaseTests
    {
        protected string[] UnkeyedTestVectors { get; set; }
        protected string[] KeyedTestVectors { get; set; }

        protected IHash HashInstanceWithKey { get; set; }

        [TestMethod]
        public void TestSplits()
        {
            Int32 LLen, LSplit1, LSplit2, LIdx;
            string LHash0, LHash1;

            byte[] LInput = new byte[20];

            for (LIdx = 0; LIdx < LInput.Length; LIdx++)
                LInput[LIdx] = (byte)LIdx;

            IHash HashInstance = hash.Clone();
            for (LLen = 0; LLen < LInput.Length; LLen++)
            {
                HashInstance.Initialize();
                HashInstance.TransformBytes(LInput, 0, LLen);
                LHash0 = HashInstance.TransformFinal().ToString();

                for (LSplit1 = 0; LSplit1 < LLen; LSplit1++)
                {
                    for (LSplit2 = LSplit1; LSplit2 < LLen; LSplit2++)
                    {
                        HashInstance.Initialize();
                        HashInstance.TransformBytes(LInput, 0, LSplit1);
                        HashInstance.TransformBytes(LInput, LSplit1, LSplit2 - LSplit1);
                        HashInstance.TransformBytes(LInput, LSplit2, LLen - LSplit2);
                        LHash1 = HashInstance.TransformFinal().ToString();

                        Assert.AreEqual(LHash0, LHash1, 
                            String.Format("Expected {0} but got {1}.", LHash0, LHash1));
                    }

                }
            }
        }

        [TestMethod]
        public void TestCheckKeyedTestVectors()
        {
            Int32 LLen, LIdx;
            byte[] LData = null;

            for (LLen = 0; LLen < KeyedTestVectors?.Length; LLen++)
            {
                if (LLen == 0) LData = null;
                else
                {
                    LData = new byte[LLen];
                    for (LIdx = 0; LIdx < LData.Length; LIdx++)
                        LData[LIdx] = (byte)LIdx;
                }

                string ActualString = HashInstanceWithKey.ComputeBytes(LData).ToString();
                string ExpectedString = KeyedTestVectors[LLen];

                Assert.AreEqual(ExpectedString, ActualString,
                    String.Format("Expected {0} but got {1}.", ExpectedString, ActualString));
            }
        }

        [TestMethod]
        public void TestCheckUnkeyedTestVectors()
        {
            Int32 LIdx, LJdx;
            byte[] LInput = null;

            for (LIdx = 0; LIdx < UnkeyedTestVectors?.Length; LIdx++)
            {
                if (LIdx == 0) LInput = null;
                else
                {
                    LInput = new byte[LIdx];
                    for (LJdx = 0; LJdx < LInput.Length; LJdx++)
                        LInput[LJdx] = (byte)LJdx;
                }

                string ActualString = hash.ComputeBytes(LInput).ToString();
                string ExpectedString = UnkeyedTestVectors[LIdx];

                Assert.AreEqual(ExpectedString, ActualString,
                    String.Format("Expected {0} but got {1}.", ExpectedString, ActualString));
            }

        }

    } 
}