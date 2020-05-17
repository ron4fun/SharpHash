using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Crypto.Blake2SConfigurations;
using SharpHash.Interfaces;
using SharpHash.Interfaces.IBlake2SConfigurations;
using SharpHash.Tests;
using SharpHash.Utils;
using System;
using System.Text;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Blake2STests : BlakeBaseTests
    {
        // https://docs.python.org/3/library/hashlib.html#tree-mode modified for Blake2s
        private static readonly string Blake2STreeHashingMode = "C81CD326CA1CA6F40E090A9D9E738892";

        public Blake2STests()
        {
            Int32 LIdx;
            IBlake2SConfig LConfig = new Blake2SConfig();

            byte[] LKey = new byte[32];

            for (LIdx = 0; LIdx < LKey.Length; LIdx++)
                LKey[LIdx] = (byte)LIdx;

            LConfig.Key = LKey;

            hash = HashFactory.Crypto.CreateBlake2S();

            HashInstanceWithKey = HashFactory.Crypto.CreateBlake2S(LConfig);

            ExpectedHashOfEmptyData = "69217A3079908094E11121D042354A7C1F55B6482CA1A51E1B250DFD1ED0EEF9";
            ExpectedHashOfDefaultData = "D9DB23D51529BC163546C2C76F9FDC4611118A691352524D6BCCF5C79AF89E14";
            ExpectedHashOfOnetoNine = "7ACC2DD21A2909140507F37396ACCE906864B5F118DFA766B107962B7A82A0D4";
            ExpectedHashOfabcde = "4BD7246C13721CC5B96F045BE71D49D5C82535332C6903771AFE9EF7B772136F";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "1CB9502C2FE830B46849F2C178BE527BF4B1B80B0B002F6FAC18C0A7ABD3B636";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "105C7994CB1F775C709A9FBC9641FB2495311258268134F460B9895915A7519A";

            UnkeyedTestVectors = Blake2STestVectors.UnkeyedBlake2S;
            KeyedTestVectors = Blake2STestVectors.KeyedBlake2S;
        }

        [TestMethod]
        public void TestNullKeyVsUnKeyed()
        {
            IBlake2SConfig ConfigNoKeyed, ConfigNullKeyed;
            byte[] MainData = null;
            Int32 i;
            
            MainData = Converters.ConvertStringToBytes(TestConstants.DefaultData, Encoding.UTF8);
            for (i = 1; i <= 32; i++)
            {
                ConfigNoKeyed = new Blake2SConfig(i);
                ConfigNullKeyed = new Blake2SConfig(i);
                ConfigNullKeyed.Key = null;

                IHash ExpectedHash = HashFactory.Crypto.CreateBlake2S(ConfigNoKeyed);
                string ExpectedString = ExpectedHash.ComputeBytes(MainData).ToString();

                IHash ActualHash = HashFactory.Crypto.CreateBlake2S(ConfigNullKeyed);
                string ActualString = ActualHash.ComputeBytes(MainData).ToString();

                Assert.AreEqual(ExpectedString, ActualString,
                    String.Format("Expected {0} but got {1} at Index {2}",
                    ExpectedString, ActualString, i));
            }
        }

        [TestMethod]
        // https://docs.python.org/3/library/hashlib.html#tree-mode modified for Blake2s
        public void TestBlake2STreeHashingMode()
        {
            const byte FAN_OUT = 2;
            const byte DEPTH = 2; // MaxDepth
            const UInt32 LEAF_SIZE = 4096;
            const byte INNER_SIZE = 32;

            IBlake2STreeConfig Blake2STreeConfigh00, Blake2STreeConfigh01, Blake2STreeConfigh10;
            IHash h00, h01, h10;

            byte[] LBuffer = new byte[6000];

            // Left leaf
            Blake2STreeConfigh00 = new Blake2STreeConfig();
            Blake2STreeConfigh00.FanOut = FAN_OUT;
            Blake2STreeConfigh00.MaxDepth = DEPTH;
            Blake2STreeConfigh00.LeafSize = LEAF_SIZE;
            Blake2STreeConfigh00.InnerHashSize = INNER_SIZE;
            Blake2STreeConfigh00.NodeOffset = 0;
            Blake2STreeConfigh00.NodeDepth = 0;
            Blake2STreeConfigh00.IsLastNode = false;
            h00 = HashFactory.Crypto.CreateBlake2S(new Blake2SConfig() as IBlake2SConfig, Blake2STreeConfigh00);
            h00.Initialize();

            // Right leaf
            Blake2STreeConfigh01 = new Blake2STreeConfig();
            Blake2STreeConfigh01.FanOut = FAN_OUT;
            Blake2STreeConfigh01.MaxDepth = DEPTH;
            Blake2STreeConfigh01.LeafSize = LEAF_SIZE;
            Blake2STreeConfigh01.InnerHashSize = INNER_SIZE;
            Blake2STreeConfigh01.NodeOffset = 1;
            Blake2STreeConfigh01.NodeDepth = 0;
            Blake2STreeConfigh01.IsLastNode = true;
            h01 = HashFactory.Crypto.CreateBlake2S(new Blake2SConfig() as IBlake2SConfig, Blake2STreeConfigh01);
            h01.Initialize();

            // Root node
            Blake2STreeConfigh10 = new Blake2STreeConfig();
            Blake2STreeConfigh10.FanOut = FAN_OUT;
            Blake2STreeConfigh10.MaxDepth = DEPTH;
            Blake2STreeConfigh10.LeafSize = LEAF_SIZE;
            Blake2STreeConfigh10.InnerHashSize = INNER_SIZE;
            Blake2STreeConfigh10.NodeOffset = 0;
            Blake2STreeConfigh10.NodeDepth = 1;
            Blake2STreeConfigh10.IsLastNode = true;
            h10 = HashFactory.Crypto.CreateBlake2S(new Blake2SConfig(16) as IBlake2SConfig, Blake2STreeConfigh10);
            h10.Initialize();

            byte[] temp = new byte[LEAF_SIZE];
            Utils.Utils.Memcopy(ref temp, LBuffer, (Int32)LEAF_SIZE);

            h10.TransformBytes(h00.ComputeBytes(temp).GetBytes());

            temp = new byte[LBuffer.Length - LEAF_SIZE];
            Utils.Utils.Memcopy(ref temp, LBuffer, (Int32)(LBuffer.Length - LEAF_SIZE), (Int32)LEAF_SIZE);

            h10.TransformBytes(h01.ComputeBytes(temp).GetBytes());

            string ActualString = h10.TransformFinal().ToString();
            string ExpectedString = Blake2STreeHashingMode;

            Assert.AreEqual(ExpectedString, ActualString,
                 String.Format("Expected {0} but got {1}.",
                 ExpectedString, ActualString));
        }

    }
}