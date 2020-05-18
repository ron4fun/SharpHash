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
using SharpHash.Crypto.Blake2BConfigurations;
using SharpHash.Interfaces;
using SharpHash.Interfaces.IBlake2BConfigurations;
using SharpHash.Tests;
using SharpHash.Utils;
using System;
using System.Text;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Blake2BTests : BlakeBaseTests
    {
        // https://docs.python.org/3/library/hashlib.html#tree-mode modified for Blake2B
        private static readonly string Blake2BTreeHashingMode = "3AD2A9B37C6070E374C7A8C508FE20CA86B6ED54E286E93A0318E95E881DB5AA";

        public Blake2BTests()
        {
            Int32 LIdx;
            IBlake2BConfig LConfig = new Blake2BConfig();

            byte[] LKey = new byte[64];

            for (LIdx = 0; LIdx < LKey.Length; LIdx++)
                LKey[LIdx] = (byte)LIdx;

            LConfig.Key = LKey;

            hash = HashFactory.Crypto.CreateBlake2B();

            HashInstanceWithKey = HashFactory.Crypto.CreateBlake2B(LConfig);

            ExpectedHashOfEmptyData = "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE";
            ExpectedHashOfDefaultData = "154F99998573B5FC21E3DF86EE1E0161A6E0E912C4361088FE46D2E3543070EFE9746E326BC09E77EC06BCA60955538821C010411B4D0D6BF9BF2D2221CC8017";
            ExpectedHashOfOnetoNine = "F5AB8BAFA6F2F72B431188AC38AE2DE7BB618FB3D38B6CBF639DEFCDD5E10A86B22FCCFF571DA37E42B23B80B657EE4D936478F582280A87D6DBB1DA73F5C47D";
            ExpectedHashOfabcde = "F3E89A60EC4B0B1854744984E421D22B82F181BD4601FB9B1726B2662DA61C29DFF09E75814ACB2639FD79E56616E55FC135F8476F0302B3DC8D44E082EB83A8";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "8E6F664622E2637AE477C00F314087FF8F6A8142D8CCF8946A451982AB750566DFD9BF97A50D705389FBF450525098797924DC443EFFDB1A1C945ECEA5DE9553";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "945EF4F96C681CC9C30A3EB1193FA13FD4ACD87D7C4A86D62AC9D8DCA74A32BB0DDC055EA75383A653E06B8E25266154DE5BE6B23C69723B795A1680EE844834";

            UnkeyedTestVectors = Blake2BTestVectors.UnkeyedBlake2B;
            KeyedTestVectors = Blake2BTestVectors.KeyedBlake2B;
        }

        [TestMethod]
        public void TestNullKeyVsUnKeyed()
        {
            IBlake2BConfig ConfigNoKeyed, ConfigNullKeyed;
            Int32 i;
            
            byte[] MainData = Converters.ConvertStringToBytes(TestConstants.DefaultData, Encoding.UTF8);

            for (i = 1; i <= 64; i++)
            {
                ConfigNoKeyed = new Blake2BConfig(i);
                ConfigNullKeyed = new Blake2BConfig(i);
                ConfigNullKeyed.Key = null;

                IHash ExpectedHash = HashFactory.Crypto.CreateBlake2B(ConfigNoKeyed);
                string ExpectedString = ExpectedHash.ComputeBytes(MainData).ToString();

                IHash ActualHash = HashFactory.Crypto.CreateBlake2B(ConfigNullKeyed);
                string ActualString = ActualHash.ComputeBytes(MainData).ToString();

                Assert.AreEqual(ExpectedString, ActualString,
                    String.Format("Expected {0} but got {1} at Index {2}",
                    ExpectedString, ActualString, i));
            }
        }

        [TestMethod]
        // https://docs.python.org/3/library/hashlib.html#tree-mode modified for Blake2B
        public void TestBlake2BTreeHashingMode()
        {
            const byte FAN_OUT = 2;
            const byte DEPTH = 2; // MaxDepth
            const UInt32 LEAF_SIZE = 4096;
            const byte INNER_SIZE = 64;

            IBlake2BTreeConfig Blake2BTreeConfigh00, Blake2BTreeConfigh01, Blake2BTreeConfigh10;
            IHash h00, h01, h10;

            byte[] LBuffer = new byte[6000];

            // Left leaf
            Blake2BTreeConfigh00 = new Blake2BTreeConfig();
            Blake2BTreeConfigh00.FanOut = FAN_OUT;
            Blake2BTreeConfigh00.MaxDepth = DEPTH;
            Blake2BTreeConfigh00.LeafSize = LEAF_SIZE;
            Blake2BTreeConfigh00.InnerHashSize = INNER_SIZE;
            Blake2BTreeConfigh00.NodeOffset = 0;
            Blake2BTreeConfigh00.NodeDepth = 0;
            Blake2BTreeConfigh00.IsLastNode = false;
            h00 = HashFactory.Crypto.CreateBlake2B(new Blake2BConfig() as IBlake2BConfig, Blake2BTreeConfigh00);
            h00.Initialize();

            // Right leaf
            Blake2BTreeConfigh01 = new Blake2BTreeConfig();
            Blake2BTreeConfigh01.FanOut = FAN_OUT;
            Blake2BTreeConfigh01.MaxDepth = DEPTH;
            Blake2BTreeConfigh01.LeafSize = LEAF_SIZE;
            Blake2BTreeConfigh01.InnerHashSize = INNER_SIZE;
            Blake2BTreeConfigh01.NodeOffset = 1;
            Blake2BTreeConfigh01.NodeDepth = 0;
            Blake2BTreeConfigh01.IsLastNode = true;
            h01 = HashFactory.Crypto.CreateBlake2B(new Blake2BConfig() as IBlake2BConfig, Blake2BTreeConfigh01);
            h01.Initialize();

            // Root node
            Blake2BTreeConfigh10 = new Blake2BTreeConfig();
            Blake2BTreeConfigh10.FanOut = FAN_OUT;
            Blake2BTreeConfigh10.MaxDepth = DEPTH;
            Blake2BTreeConfigh10.LeafSize = LEAF_SIZE;
            Blake2BTreeConfigh10.InnerHashSize = INNER_SIZE;
            Blake2BTreeConfigh10.NodeOffset = 0;
            Blake2BTreeConfigh10.NodeDepth = 1;
            Blake2BTreeConfigh10.IsLastNode = true;
            h10 = HashFactory.Crypto.CreateBlake2B(new Blake2BConfig(32) as IBlake2BConfig, Blake2BTreeConfigh10);
            h10.Initialize();

            byte[] temp = new byte[LEAF_SIZE];
            Utils.Utils.Memcopy(ref temp, LBuffer, (Int32)LEAF_SIZE);

            h10.TransformBytes(h00.ComputeBytes(temp).GetBytes());

            temp = new byte[LBuffer.Length - LEAF_SIZE];
            Utils.Utils.Memcopy(ref temp, LBuffer, (Int32)(LBuffer.Length - LEAF_SIZE), (Int32)LEAF_SIZE);

            h10.TransformBytes(h01.ComputeBytes(temp).GetBytes());

            string ActualString = h10.TransformFinal().ToString();
            string ExpectedString = Blake2BTreeHashingMode;

            Assert.AreEqual(ExpectedString, ActualString,
                 String.Format("Expected {0} but got {1}.",
                 ExpectedString, ActualString));
        }

    }
}