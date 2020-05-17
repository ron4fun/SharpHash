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