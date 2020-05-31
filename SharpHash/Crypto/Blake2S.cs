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

using SharpHash.Base;
using SharpHash.Crypto.Blake2SConfigurations;
using SharpHash.Interfaces;
using SharpHash.Interfaces.IBlake2SConfigurations;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal class Blake2S : Hash, ICryptoNotBuiltIn, ITransformBlock
    {
        public static readonly string InvalidConfigLength = "Config Length Must Be 8 Words";
        public static readonly string ConfigNil = "Config Cannot Be Nil";
        public static readonly string InvalidXOFSize = "XOFSize in Bits must be Multiples of 8 and be Between {0} and {1} Bytes.";
        public static readonly string OutputLengthInvalid = "Output Length is above the Digest Length";
        public static readonly string OutputBufferTooShort = "Output Buffer Too Short";
        public static readonly string MaximumOutputLengthExceeded = "Maximum Length is 2^32 blocks of 32 bytes";
        public static readonly string WritetoXofAfterReadError = "\"{0}\" Write to Xof after Read not Allowed";

        protected UInt32[] State = null;
        protected UInt32[] M = null;
        protected byte[] Buffer = null;

        protected Int32 FilledBufferCount { get; set; }
        protected UInt32 Counter0 { get; set; }
        protected UInt32 Counter1 { get; set; }
        protected UInt32 FinalizationFlag0 { get; set; }
        protected UInt32 FinalizationFlag1 { get; set; }

        protected IBlake2STreeConfig TreeConfig = null;
        protected IBlake2SConfig Config = null;
        private bool DoTransformKeyBlock;

        private const Int32 BlockSizeInBytes = 64;

        private const UInt32 IV0 = unchecked((UInt32)0x66A09E667);
        private const UInt32 IV1 = 0xBB67AE85;
        private const UInt32 IV2 = 0x3C6EF372;
        private const UInt32 IV3 = 0xA54FF53A;
        private const UInt32 IV4 = 0x510E527F;
        private const UInt32 IV5 = 0x9B05688C;
        private const UInt32 IV6 = 0x1F83D9AB;
        private const UInt32 IV7 = 0x5BE0CD19;

        public Blake2S()
            : this(new Blake2SConfig())
        { }

        public Blake2S(IBlake2SConfig a_Config)
            : this(a_Config, null)
        { }

        public Blake2S(IBlake2SConfig a_Config, IBlake2STreeConfig a_TreeConfig, bool a_DoTransformKeyBlock = true)
            : base(a_Config?.HashSize ?? -1, BlockSizeInBytes)
        {
            Config = a_Config;
            TreeConfig = a_TreeConfig;
            DoTransformKeyBlock = a_DoTransformKeyBlock;

            if (Config == null)
                Config = Blake2SConfig.DefaultConfig;

            // Reset HashSize
            HashSize = Config.HashSize;

            State = new UInt32[8];
            M = new UInt32[16];

            Buffer = new byte[BlockSizeInBytes];
        }

        public override string Name => String.Format("{0}_{1}", this.GetType().Name, HashSize * 8);

        public Blake2S CloneInternal()
        {
            Blake2S result = new Blake2S(Config.Clone(), TreeConfig?.Clone(), DoTransformKeyBlock);

            result.State = State.DeepCopy();
            result.M = M.DeepCopy();
            result.Buffer = Buffer.DeepCopy();

            result.FilledBufferCount = FilledBufferCount;
            result.Counter0 = Counter0;
            result.Counter1 = Counter1;
            result.FinalizationFlag0 = FinalizationFlag0;
            result.FinalizationFlag1 = FinalizationFlag1;

            result.BufferSize = BufferSize;

            return result;
        }

        public override IHash Clone()
        {
            return CloneInternal();
        }

        public override unsafe void Initialize()
        {
            Int32 Idx;
            byte[] block = null;

            UInt32[] RawConfig = Blake2SIvBuilder.ConfigS(Config, TreeConfig);

            if (DoTransformKeyBlock)
            {
                if (!Config.Key.Empty())
                {
                    block = Config.Key.DeepCopy();
                    Array.Resize(ref block, BlockSizeInBytes);
                }
            }

            if (RawConfig.Empty())
                throw new ArgumentNullHashLibException(ConfigNil);

            if (RawConfig.Length != 8)
                throw new ArgumentHashLibException(InvalidConfigLength);

            State[0] = IV0;
            State[1] = IV1;
            State[2] = IV2;
            State[3] = IV3;
            State[4] = IV4;
            State[5] = IV5;
            State[6] = IV6;
            State[7] = IV7;

            Counter0 = 0;
            Counter1 = 0;
            FinalizationFlag0 = 0;
            FinalizationFlag1 = 0;

            FilledBufferCount = 0;

            ArrayUtils.ZeroFill(ref Buffer);
            ArrayUtils.ZeroFill(ref M);

            for (Idx = 0; Idx < 8; Idx++)
                State[Idx] = State[Idx] ^ RawConfig[Idx];

            if (DoTransformKeyBlock)
            {
                if (!block.Empty())
                {
                    TransformBytes(block, 0, block.Length);
                    ArrayUtils.ZeroFill(ref block); // burn key from memory
                }
            }

        } // end function Initialize

        public override unsafe void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            Int32 offset, bufferRemaining;

            offset = a_index;
            bufferRemaining = BlockSizeInBytes - FilledBufferCount;

            if ((FilledBufferCount > 0) && (a_length > bufferRemaining))
            {
                if (bufferRemaining > 0)
                    Utils.Utils.Memmove(ref Buffer, a_data, bufferRemaining, offset, FilledBufferCount);

                Blake2SIncrementCounter((UInt32)BlockSizeInBytes);
                Compress(ref Buffer, 0);
                offset = offset + bufferRemaining;
                a_length = a_length - bufferRemaining;
                FilledBufferCount = 0;
            }

            while (a_length > BlockSizeInBytes)
            {
                Blake2SIncrementCounter((UInt32)BlockSizeInBytes);
                Compress(ref a_data, offset);
                offset = offset + BlockSizeInBytes;
                a_length = a_length - BlockSizeInBytes;
            }

            if (a_length > 0)
            {
                Utils.Utils.Memmove(ref Buffer, a_data, a_length, offset, FilledBufferCount);
                FilledBufferCount = FilledBufferCount + a_length;
            }

        }

        public override unsafe IHashResult TransformFinal()
        {
            Finish();

            byte[] tempRes = new byte[HashSize];

            fixed (UInt32* statePtr = State)
            {
                fixed (byte* tempResPtr = tempRes)
                {
                    Converters.le32_copy((IntPtr)statePtr, 0, (IntPtr)tempResPtr, 0,
                        tempRes.Length);
                }
            }

            IHashResult result = new HashResult(tempRes);

            Initialize();

            return result;
        }

        private void Blake2SIncrementCounter(UInt32 a_IncrementCount)
        {
            Counter0 = Counter0 + a_IncrementCount;
            Counter1 = Counter1 + (UInt32)(Counter0 < a_IncrementCount ? 1 : 0);
        } // end function Blake2SIncrementCounter

        private void MixScalar()
        {
            UInt32 m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, v0, v1, 
                v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15;

            m0 = M[0];
            m1 = M[1];
            m2 = M[2];
            m3 = M[3];
            m4 = M[4];
            m5 = M[5];
            m6 = M[6];
            m7 = M[7];
            m8 = M[8];
            m9 = M[9];
            m10 = M[10];
            m11 = M[11];
            m12 = M[12];
            m13 = M[13];
            m14 = M[14];
            m15 = M[15];

            v0 = State[0];
            v1 = State[1];
            v2 = State[2];
            v3 = State[3];
            v4 = State[4];
            v5 = State[5];
            v6 = State[6];
            v7 = State[7];

            v8 = IV0;
            v9 = IV1;
            v10 = IV2;
            v11 = IV3;
            v12 = IV4 ^ Counter0;
            v13 = IV5 ^ Counter1;
            v14 = IV6 ^ FinalizationFlag0;
            v15 = IV7 ^ FinalizationFlag1;

            // Rounds
            // *
            // Round 1.
            v0 = v0 + m0;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 = v1 + m2;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 = v2 + m4;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 = v3 + m6;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 = v2 + m5;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 = v3 + m7;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 = v1 + m3;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 = v0 + m1;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 = v0 + m8;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 = v1 + m10;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 = v2 + m12;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 = v3 + m14;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 = v2 + m13;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 = v3 + m15;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 = v1 + m11;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 = v0 + m9;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 2.
            v0 = v0 + m14;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 = v1 + m4;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 = v2 + m9;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 = v3 + m13;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 = v2 + m15;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 = v3 + m6;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 = v1 + m8;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 = v0 + m10;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 = v0 + m1;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 = v1 + m0;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 = v2 + m11;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 = v3 + m5;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 = v2 + m7;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 = v3 + m3;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 = v1 + m2;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 = v0 + m12;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 3.
            v0 = v0 + m11;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 = v1 + m12;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 = v2 + m5;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 = v3 + m15;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 = v2 + m2;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 = v3 + m13;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 = v1 + m0;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 = v0 + m8;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 = v0 + m10;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 = v1 + m3;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 = v2 + m7;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 = v3 + m9;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 = v2 + m1;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 = v3 + m4;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 = v1 + m6;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 = v0 + m14;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 4.
            v0 = v0 + m7;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 = v1 + m3;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 = v2 + m13;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 = v3 + m11;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 = v2 + m12;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 = v3 + m14;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 = v1 + m1;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 = v0 + m9;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 = v0 + m2;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 = v1 + m5;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 = v2 + m4;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 = v3 + m15;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 = v2 + m0;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 = v3 + m8;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 = v1 + m10;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 = v0 + m6;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 5.
            v0 = v0 + m9;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 = v1 + m5;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 = v2 + m2;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 = v3 + m10;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 = v2 + m4;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 = v3 + m15;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 = v1 + m7;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 = v0 + m0;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 = v0 + m14;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 = v1 + m11;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 = v2 + m6;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 = v3 + m3;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 = v2 + m8;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 = v3 + m13;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 = v1 + m12;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 = v0 + m1;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 6.
            v0 = v0 + m2;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 = v1 + m6;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 = v2 + m0;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 = v3 + m8;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 = v2 + m11;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 = v3 + m3;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 = v1 + m10;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 = v0 + m12;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 = v0 + m4;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 = v1 + m7;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 = v2 + m15;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 = v3 + m1;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 = v2 + m14;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 = v3 + m9;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 = v1 + m5;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 = v0 + m13;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 7.
            v0 = v0 + m12;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 = v1 + m1;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 = v2 + m14;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 = v3 + m4;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 = v2 + m13;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 = v3 + m10;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 = v1 + m15;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 = v0 + m5;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 = v0 + m0;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 = v1 + m6;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 = v2 + m9;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 = v3 + m8;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 = v2 + m2;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 = v3 + m11;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 = v1 + m3;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 = v0 + m7;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 8.
            v0 = v0 + m13;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 = v1 + m7;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 = v2 + m12;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 = v3 + m3;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 = v2 + m1;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 = v3 + m9;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 = v1 + m14;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 = v0 + m11;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 = v0 + m5;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 = v1 + m15;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 = v2 + m8;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 = v3 + m2;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 = v2 + m6;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 = v3 + m10;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 = v1 + m4;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 = v0 + m0;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 9.
            v0 = v0 + m6;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 = v1 + m14;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 = v2 + m11;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 = v3 + m0;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 = v2 + m3;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 = v3 + m8;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 = v1 + m9;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 = v0 + m15;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 = v0 + m12;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 = v1 + m13;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 = v2 + m1;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 = v3 + m10;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 = v2 + m4;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 = v3 + m5;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 = v1 + m7;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 = v0 + m2;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 10.
            v0 = v0 + m10;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 = v1 + m8;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 = v2 + m7;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 = v3 + m1;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 = v2 + m6;
            v2 = v2 + v6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 = v3 + m5;
            v3 = v3 + v7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 = v1 + m4;
            v1 = v1 + v5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 = v0 + m2;
            v0 = v0 + v4;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 = v0 + m15;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 = v1 + m9;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 = v2 + m3;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 = v3 + m13;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 = v2 + m12;
            v2 = v2 + v7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 = v3 + m0;
            v3 = v3 + v4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 = v1 + m14;
            v1 = v1 + v6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 = v0 + m11;
            v0 = v0 + v5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight32(v5, 7);
            // */
            // Finalization

            State[0] = State[0] ^ (v0 ^ v8);
            State[1] = State[1] ^ (v1 ^ v9);
            State[2] = State[2] ^ (v2 ^ v10);
            State[3] = State[3] ^ (v3 ^ v11);
            State[4] = State[4] ^ (v4 ^ v12);
            State[5] = State[5] ^ (v5 ^ v13);
            State[6] = State[6] ^ (v6 ^ v14);
            State[7] = State[7] ^ (v7 ^ v15);

        } // end function MixScalar

        private unsafe void Compress(ref byte[] block, Int32 start)
        {
            fixed (UInt32* MPtr = M)
            {
                fixed (byte* blockPtr = block)
                {
                    Converters.le32_copy((IntPtr)blockPtr, start, (IntPtr)MPtr, 0, BlockSize);
                }
            }

            MixScalar();
        } // end function Compress

        protected unsafe void Finish()
        {
            Int32 count;

            // Last compression
            Blake2SIncrementCounter((UInt32)FilledBufferCount);

            FinalizationFlag0 = UInt32.MaxValue;

            if (TreeConfig != null && TreeConfig.IsLastNode)
                FinalizationFlag1 = UInt32.MaxValue;

            count = Buffer.Length - FilledBufferCount;

            if (count > 0)
                ArrayUtils.Fill(ref Buffer, FilledBufferCount, count + FilledBufferCount, (byte)0);

            Compress(ref Buffer, 0);
        } // end function Finish

    } // end class Blake2S


    internal sealed class Blake2XS : Blake2S, IXOF
    {
        private IBlake2XSConfig Blake2XSConfig = null;
        private UInt64 DigestPosition;
        private IBlake2XSConfig RootConfig = null;
        private IBlake2XSConfig OutputConfig = null;
        private byte[] RootHashDigest = null;
        private byte[] Blake2XSBuffer = null;
        private bool Finalized;

        private UInt64 _XofSizeInBits;
        public UInt64 XOFSizeInBits
        {
            get => _XofSizeInBits;
            set => SetXOFSizeInBitsInternal(value);
        }

        private const Int32 Blake2SHashSize = 32;

        // Magic number to indicate an unknown length of digest
        private const UInt16 UnknownDigestLengthInBytes = (UInt16)(((UInt32)1 << 16) - 1); // 65535 bytes
        private const UInt64 MaxNumberBlocks = (UInt64)1 << 32;

        // 2^32 blocks of 32 bytes (128GiB)
        // the maximum size in bytes the digest can produce when the length is unknown
        private const UInt64 UnknownMaxDigestLengthInBytes = (UInt64)(MaxNumberBlocks * (UInt64)Blake2SHashSize);


        public override string Name
        {
            get => this.GetType().Name;
        } // end property Name

        public unsafe void DoOutput(ref byte[] a_destination, UInt64 a_destinationOffset, UInt64 a_outputLength)
        {
            UInt64 diff, blockOffset, count;

            if (((UInt64)a_destination.Length - a_destinationOffset) < a_outputLength)
                throw new ArgumentOutOfRangeHashLibException(OutputBufferTooShort);

            if ((XOFSizeInBits >> 3) != UnknownDigestLengthInBytes)
            {
                if ((DigestPosition + a_outputLength) > (XOFSizeInBits >> 3))
                    throw new ArgumentOutOfRangeHashLibException(OutputLengthInvalid);
            }
            else if (DigestPosition == UnknownMaxDigestLengthInBytes)
                throw new ArgumentOutOfRangeHashLibException(MaximumOutputLengthExceeded);

            if (!Finalized)
            {
                Finish();
                Finalized = true;
            }
            
            if (RootHashDigest.Empty())
            {
                // Get root digest
                RootHashDigest = new byte[Blake2SHashSize];
                fixed (UInt32* statePtr = State)
                {
                    fixed (byte* RootHashDigestPtr = RootHashDigest)
                    {
                        Converters.le32_copy((IntPtr)statePtr, 0, (IntPtr)RootHashDigestPtr, 0,
                            RootHashDigest.Length);
                    }
                }
            }

            while (a_outputLength > 0)
            {
                if ((DigestPosition & (Blake2SHashSize - 1)) == 0)
                {
                    OutputConfig.Blake2SConfig.HashSize = ComputeStepLength();
                    OutputConfig.Blake2STreeConfig.InnerHashSize = (byte)Blake2SHashSize;

                    Blake2XSBuffer = (new Blake2S(OutputConfig.Blake2SConfig, OutputConfig.Blake2STreeConfig) as IHash).ComputeBytes(RootHashDigest).GetBytes();
                    OutputConfig.Blake2STreeConfig.NodeOffset = OutputConfig.Blake2STreeConfig.NodeOffset + 1;
                }

                blockOffset = DigestPosition & (Blake2SHashSize - 1);

                diff = (UInt64)Blake2XSBuffer.Length - blockOffset;

                count = Math.Min(a_outputLength, diff);

                Utils.Utils.Memmove(ref a_destination, Blake2XSBuffer, (Int32)count, (Int32)blockOffset, (Int32)a_destinationOffset);

                a_outputLength -= count;
                a_destinationOffset += count;
                DigestPosition += count;
            }

        }
        
        public Blake2XS(IBlake2XSConfig a_Blake2XSConfig)
        {
            Blake2XSConfig = a_Blake2XSConfig;

            // Create root hash config.
            RootConfig = new Blake2XSConfig();

            RootConfig.Blake2SConfig = Blake2XSConfig.Blake2SConfig;

            if (RootConfig.Blake2SConfig == null)
                RootConfig.Blake2SConfig = new Blake2SConfig();
            else
            {
                RootConfig.Blake2SConfig.Key = Blake2XSConfig.Blake2SConfig.Key;
                RootConfig.Blake2SConfig.Salt = Blake2XSConfig.Blake2SConfig.Salt;
                RootConfig.Blake2SConfig.Personalisation = Blake2XSConfig.Blake2SConfig.Personalisation;
            }

            RootConfig.Blake2STreeConfig = Blake2XSConfig.Blake2STreeConfig;

            if (RootConfig.Blake2STreeConfig == null)
            {
                RootConfig.Blake2STreeConfig = new Blake2STreeConfig();
                RootConfig.Blake2STreeConfig.FanOut = 1;
                RootConfig.Blake2STreeConfig.MaxDepth = 1;

                RootConfig.Blake2STreeConfig.LeafSize = 0;
                RootConfig.Blake2STreeConfig.NodeOffset = 0;
                RootConfig.Blake2STreeConfig.NodeDepth = 0;
                RootConfig.Blake2STreeConfig.InnerHashSize = 0;
                RootConfig.Blake2STreeConfig.IsLastNode = false;
            }

            // Create initial config for output hashes.
            OutputConfig = new Blake2XSConfig();

            OutputConfig.Blake2SConfig = new Blake2SConfig();
            OutputConfig.Blake2SConfig.Salt = RootConfig.Blake2SConfig.Salt;
            OutputConfig.Blake2SConfig.Personalisation = RootConfig.Blake2SConfig.Personalisation;

            OutputConfig.Blake2STreeConfig = new Blake2STreeConfig();

            // Initialise base Blake2S configs
            Config = RootConfig.Blake2SConfig;
            TreeConfig = RootConfig.Blake2STreeConfig;
            HashSize = Config.HashSize;

            Blake2XSBuffer = new byte[Blake2SHashSize];
        } // end cctr 
        
        public override void Initialize()
        {
            UInt64 xofSizeInBytes = XOFSizeInBits >> 3;

            RootConfig.Blake2STreeConfig.NodeOffset = NodeOffsetWithXOFDigestLength(xofSizeInBytes);

            OutputConfig.Blake2STreeConfig.NodeOffset = NodeOffsetWithXOFDigestLength(xofSizeInBytes);
                        
            RootHashDigest = null;
            DigestPosition = 0;
            Finalized = false;
            ArrayUtils.ZeroFill(ref Blake2XSBuffer);

            base.Initialize();
        } // end function Initialize

        public override IHash Clone()
        {
            // Xof Cloning
            IXOF Xof = (new Blake2XS(Blake2XSConfig) as IXOF);
            Xof.XOFSizeInBits = (this as IXOF).XOFSizeInBits;

            // Blake2XS Cloning
            Blake2XS HashInstance = (Xof as Blake2XS);
            HashInstance.Blake2XSConfig = Blake2XSConfig.Clone();
            HashInstance.DigestPosition = DigestPosition;
            HashInstance.RootConfig = RootConfig.Clone();
            HashInstance.OutputConfig = OutputConfig.Clone();
            HashInstance.Finalized = Finalized;

            HashInstance.RootHashDigest = RootHashDigest.DeepCopy();
            HashInstance.Blake2XSBuffer = Blake2XSBuffer.DeepCopy();
            
            HashInstance.M = M.DeepCopy();
            HashInstance.State = State.DeepCopy();
            HashInstance.Buffer = Buffer.DeepCopy();
            
            HashInstance.FilledBufferCount = FilledBufferCount;
            HashInstance.Counter0 = Counter0;
            HashInstance.Counter1 = Counter1;
            HashInstance.FinalizationFlag0 = FinalizationFlag0;
            HashInstance.FinalizationFlag1 = FinalizationFlag1;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        }

        public override unsafe void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            if (Finalized)
                throw new InvalidOperationHashLibException(
                    String.Format(WritetoXofAfterReadError, Name));

            base.TransformBytes(a_data, a_index, a_length);
        } // end function TransformBytes

        public override IHashResult TransformFinal()
        {
            byte[] buffer = GetResult();

            IHashResult result = new HashResult(buffer);

            Initialize();

            return result;
        }

        private IXOF SetXOFSizeInBitsInternal(UInt64 a_XofSizeInBits)
        {
            UInt64 xofSizeInBytes = a_XofSizeInBits >> 3;
            if (((a_XofSizeInBits & 0x7) != 0) || (xofSizeInBytes < 1) ||
                (xofSizeInBytes > (UInt64)UnknownDigestLengthInBytes))
                throw new ArgumentInvalidHashLibException(
                    String.Format(InvalidXOFSize, 1, (UInt64)UnknownDigestLengthInBytes));

            _XofSizeInBits = a_XofSizeInBits;

            return this;
        }

        private UInt64 NodeOffsetWithXOFDigestLength(UInt64 a_XOFSizeInBytes)
        {
            return (UInt64)a_XOFSizeInBytes << 32;
        }

        private Int32 ComputeStepLength()
        {
            UInt64 xofSizeInBytes, diff;

            xofSizeInBytes = XOFSizeInBits >> 3;
            diff = xofSizeInBytes - DigestPosition;

            if (xofSizeInBytes == (UInt64)UnknownDigestLengthInBytes)
                return Blake2SHashSize;

            return (Int32)Math.Min((UInt64)Blake2SHashSize, diff);
        }

        private byte[] GetResult()
        {
            UInt64 xofSizeInBytes = XOFSizeInBits >> 3;

            byte[] result = new byte[xofSizeInBytes];

            DoOutput(ref result, 0, xofSizeInBytes);

            return result;
        }

    } // end class Blake2XS

    internal sealed class Blake2SMACNotBuildInAdapter : Hash, IBlake2SMACNotBuiltIn, ICryptoNotBuiltIn
    {
        private IHash hash = null;

        private byte[] key = null;
        public byte[] Key
        {
            get => key;
            set => key = value;
        }

        ~Blake2SMACNotBuildInAdapter()
        {
            Clear();
        }

        public override IHash Clone()
        {
            Blake2SMACNotBuildInAdapter HashInstance = new Blake2SMACNotBuildInAdapter(hash, Key);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        }

        public void Clear()
        {
            ArrayUtils.ZeroFill(ref key);
        }

        public override unsafe void Initialize()
        {
            hash?.Initialize();
        }

        public override IHashResult TransformFinal()
        {
            return hash?.TransformFinal();
        }

        public override void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            hash?.TransformBytes(a_data, a_index, a_length);
        }

        public static IBlake2SMAC CreateBlake2SMAC(byte[] a_Blake2SKey, byte[] a_Salt, byte[] a_Personalisation, Int32 a_OutputLengthInBits)
        {
            IBlake2SConfig config = new Blake2SConfig(a_OutputLengthInBits >> 3);

            config.Key = a_Blake2SKey.DeepCopy();
            config.Salt = a_Salt.DeepCopy();
            config.Personalisation = a_Personalisation.DeepCopy();                       

            return new Blake2SMACNotBuildInAdapter(new Blake2S(config, null), a_Blake2SKey);
        }

        private Blake2SMACNotBuildInAdapter(IHash a_Hash, byte[] a_Blake2SKey)
            : base(a_Hash?.HashSize ?? -1, a_Hash?.BlockSize ?? -1)
        {
            Key = a_Blake2SKey.DeepCopy();

            hash = a_Hash?.Clone();
        }

    } // end class Blake2SMACNotBuildInAdapter

}
