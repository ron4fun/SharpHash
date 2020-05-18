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
using SharpHash.Crypto.Blake2BConfigurations;
using SharpHash.Interfaces;
using SharpHash.Interfaces.IBlake2BConfigurations;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal class Blake2B : Hash, ICryptoNotBuildIn, ITransformBlock
    {
        public static readonly string InvalidConfigLength = "Config Length Must Be 8 Words";
        public static readonly string ConfigNil = "Config Cannot Be Nil";
        public static readonly string InvalidXOFSize = "XOFSize in Bits must be Multiples of 8 and be Between {0} and {1} Bytes.";
        public static readonly string OutputLengthInvalid = "Output Length is above the Digest Length";
        public static readonly string OutputBufferTooShort = "Output Buffer Too Short";
        public static readonly string MaximumOutputLengthExceeded = "Maximum Length is 2^32 blocks of 64 bytes";
        public static readonly string WritetoXofAfterReadError = "\"{0}\" Write to Xof after Read not Allowed";

        protected UInt64[] State = null;
        protected UInt64[] M = null;
        protected byte[] Buffer = null;

        protected Int32 FilledBufferCount { get; set; }
        protected UInt64 Counter0 { get; set; }
        protected UInt64 Counter1 { get; set; }
        protected UInt64 FinalizationFlag0 { get; set; }
        protected UInt64 FinalizationFlag1 { get; set; }

        protected IBlake2BTreeConfig TreeConfig = null;
        protected IBlake2BConfig Config = null;
        private bool DoTransformKeyBlock;

        private static readonly Int32 BlockSizeInBytes = 128;

        private static readonly UInt64 IV0 = 0x6A09E667F3BCC908;
        private static readonly UInt64 IV1 = 0xBB67AE8584CAA73B;
        private static readonly UInt64 IV2 = 0x3C6EF372FE94F82B;
        private static readonly UInt64 IV3 = 0xA54FF53A5F1D36F1;
        private static readonly UInt64 IV4 = 0x510E527FADE682D1;
        private static readonly UInt64 IV5 = 0x9B05688C2B3E6C1F;
        private static readonly UInt64 IV6 = 0x1F83D9ABFB41BD6B;
        private static readonly UInt64 IV7 = 0x5BE0CD19137E2179;

        public Blake2B()
            : this(new Blake2BConfig())
        { }

        public Blake2B(IBlake2BConfig a_Config)
            : this(a_Config, null)
        { }

        public Blake2B(IBlake2BConfig a_Config, IBlake2BTreeConfig a_TreeConfig, 
            bool a_DoTransformKeyBlock = true) 
            : base(a_Config?.HashSize ?? -1, BlockSizeInBytes)
        {
            Config = a_Config;
            TreeConfig = a_TreeConfig;
            DoTransformKeyBlock = a_DoTransformKeyBlock;

            if (Config == null)
                Config = Blake2BConfig.GetDefaultConfig();

            // Reset HashSize
            HashSize = Config.HashSize;

            State = new UInt64[8];
            M = new UInt64[16];          

            Buffer = new byte[BlockSizeInBytes];
        }

        private void Blake2BIncrementCounter(UInt64 a_IncrementCount)
        {
            Counter0 = Counter0 + a_IncrementCount;
            Counter1 = Counter1 + (UInt64)(Counter0 < a_IncrementCount ? 1 : 0);
        } // end function Blake2BIncrementCounter

        public Blake2B CloneInternal()
        {
            Blake2B result = new Blake2B(Config.Clone(), TreeConfig?.Clone(), DoTransformKeyBlock);

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

        public override string Name
        {
            get
            {
                return String.Format("{0}_{1}", this.GetType().Name, HashSize * 8);
            }
        } // end property Name

        public override IHash Clone()
        {
            return CloneInternal();
        }

        public override unsafe void Initialize()
        {
            Int32 Idx;
            byte[] Block = null;

            UInt64[] RawConfig = Blake2BIvBuilder.ConfigB(Config, TreeConfig);

            if (DoTransformKeyBlock)
            {
                if (!Config.Key.Empty())
                {
                    Block = Config.Key.DeepCopy();
                    Array.Resize(ref Block, BlockSizeInBytes);
                }
            }

            if (RawConfig.Empty())
                throw new ArgumentNilHashLibException(ConfigNil);

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
                if (!Block.Empty())
                {
                    TransformBytes(Block, 0, Block.Length);
                    ArrayUtils.ZeroFill(ref Block); // burn key from memory
                }
            }
        }

        public override unsafe void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            Int32 offset, bufferRemaining;

            offset = a_index;
            bufferRemaining = BlockSizeInBytes - FilledBufferCount;

            if ((FilledBufferCount > 0) && (a_length > bufferRemaining))
            {
                if (bufferRemaining > 0)
                    Utils.Utils.Memmove(ref Buffer, a_data, bufferRemaining, offset, FilledBufferCount);

                Blake2BIncrementCounter((UInt64)BlockSizeInBytes);
                Compress(ref Buffer, 0);
                offset = offset + bufferRemaining;
                a_length = a_length - bufferRemaining;
                FilledBufferCount = 0;
            }

            while (a_length > BlockSizeInBytes)
            {
                Blake2BIncrementCounter((UInt64)BlockSizeInBytes);
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

            fixed (UInt64* statePtr = State)
            {
                fixed (byte* tempResPtr = tempRes)
                {
                    Converters.le64_copy((IntPtr)statePtr, 0, (IntPtr)tempResPtr, 0,
                        tempRes.Length);
                }
            }

            IHashResult result = new HashResult(tempRes);

            Initialize();

            return result;
        }

        private void MixScalar()
        {
            UInt64 m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, v0, v1,
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

            // ##### Round(0)
            // G(0, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m0;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m1;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(0, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m2;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m3;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(0, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m4;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m5;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(0, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m6;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(0, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m8;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m9;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(0, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m10;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m11;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(0, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m12;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m13;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(0, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m14;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m15;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(1)
            // G(1, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m14;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m10;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(1, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m4;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m8;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(1, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m9;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m15;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(1, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m13;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m6;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(1, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m1;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m12;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(1, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m0;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m2;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(1, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m11;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(1, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m5;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m3;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(2)
            // G(2, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m11;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m8;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(2, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m12;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m0;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(2, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m5;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m2;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(2, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m15;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m13;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(2, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m10;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m14;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(2, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m3;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(2, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m1;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(2, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m9;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m4;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(3)
            // G(3, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m7;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m9;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(3, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m3;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m1;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(3, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m13;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m12;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(3, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m11;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m14;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(3, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m2;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m6;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(3, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m5;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m10;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(3, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m4;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m0;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(3, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m15;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m8;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(4)
            // G(4, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m9;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m0;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(4, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m5;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m7;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(4, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m2;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m4;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(4, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m10;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m15;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(4, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m14;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m1;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(4, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m11;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m12;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(4, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m6;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m8;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(4, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m3;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m13;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(5)
            // G(5, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m2;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m12;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(5, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m6;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m10;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(5, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m0;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m11;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(5, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m8;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m3;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(5, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m4;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m13;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(5, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m7;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m5;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(5, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m15;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m14;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(5, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m1;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m9;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(6)
            // G(6, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m12;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m5;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(6, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m1;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m15;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(6, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m14;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m13;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(6, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m4;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m10;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(6, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m0;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m7;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(6, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m6;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m3;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(6, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m9;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m2;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(6, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m8;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m11;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(7)
            // G(7, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m13;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m11;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(7, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m7;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m14;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(7, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m12;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m1;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(7, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m3;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m9;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(7, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m5;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m0;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(7, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m15;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m4;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(7, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m8;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m6;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(7, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m2;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m10;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(8)
            // G(8, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m6;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m15;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(8, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m14;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m9;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(8, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m11;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m3;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(8, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m0;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m8;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(8, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m12;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m2;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(8, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m13;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m7;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(8, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m1;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m4;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(8, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m10;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m5;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(9)
            // G(9, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m10;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m2;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(9, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m8;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m4;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(9, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m7;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m6;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(9, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m1;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m5;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(9, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m15;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m11;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(9, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m9;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m14;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(9, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m3;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m12;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(9, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m13;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m0;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(10)
            // G(10, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m0;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m1;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(10, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m2;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m3;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(10, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m4;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m5;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(10, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m6;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m7;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(10, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m8;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m9;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(10, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m10;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m11;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(10, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m12;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m13;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(10, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m14;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m15;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(11)
            // G(11, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m14;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m10;
            v12 = v12 ^ v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 = v8 + v12;
            v4 = v4 ^ v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(11, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m4;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m8;
            v13 = v13 ^ v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 = v9 + v13;
            v5 = v5 ^ v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(11, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m9;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m15;
            v14 = v14 ^ v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 = v10 + v14;
            v6 = v6 ^ v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(11, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m13;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m6;
            v15 = v15 ^ v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 = v11 + v15;
            v7 = v7 ^ v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(11, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m1;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m12;
            v15 = v15 ^ v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 = v10 + v15;
            v5 = v5 ^ v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(11, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m0;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m2;
            v12 = v12 ^ v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 = v11 + v12;
            v6 = v6 ^ v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(11, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m11;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m7;
            v13 = v13 ^ v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 = v8 + v13;
            v7 = v7 ^ v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(11, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m5;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m3;
            v14 = v14 ^ v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 = v9 + v14;
            v4 = v4 ^ v9;
            v4 = Bits.RotateRight64(v4, 63);

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
            fixed (UInt64* MPtr = M)
            {
                fixed (byte* blockPtr = block)
                {
                    Converters.le64_copy((IntPtr)blockPtr, start, (IntPtr)MPtr, 0, BlockSize);
                }
            }

            MixScalar();
        }

        protected unsafe void Finish()
        {
            Int32 count;

            // Last compression
            Blake2BIncrementCounter((UInt64)FilledBufferCount);

            FinalizationFlag0 = UInt64.MaxValue;

            if (TreeConfig != null && TreeConfig.IsLastNode)
                FinalizationFlag1 = UInt64.MaxValue;

            count = Buffer.Length - FilledBufferCount;

            if (count > 0)
                ArrayUtils.Fill(ref Buffer, FilledBufferCount, count + FilledBufferCount, (byte)0);

            Compress(ref Buffer, 0);
        } // end function Finish

    } // end class Blake2B

    internal sealed class Blake2XB : Blake2B, IXOF
    {
        private IBlake2XBConfig Blake2XBConfig = null;
        private UInt64 DigestPosition;
        private IBlake2XBConfig RootConfig = null;
        private IBlake2XBConfig OutputConfig = null;
        private byte[] RootHashDigest = null;
        private byte[] Blake2XBBuffer = null;
        private bool Finalized;

        UInt64 xofSizeInBits;
        public UInt64 XOFSizeInBits
        {
            get => xofSizeInBits;
            set => SetXOFSizeInBitsInternal(value);
        }

        private static readonly Int32 Blake2BHashSize = 64;

        // Magic number to indicate an unknown length of digest
        private static readonly UInt64 UnknownDigestLengthInBytes = (UInt64)(((UInt64)1 << 32) - 1); // 4294967295 bytes
        private static readonly UInt64 MaxNumberBlocks = (UInt64)1 << 32;

        // 2^32 blocks of 32 bytes (128GiB)
        // the maximum size in bytes the digest can produce when the length is unknown
        private static readonly UInt64 UnknownMaxDigestLengthInBytes = (UInt64)(MaxNumberBlocks * (UInt64)Blake2BHashSize);


        public override string Name
        {
            get
            {
                return this.GetType().Name;
            }
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
            else if ((DigestPosition << 5) >= UnknownMaxDigestLengthInBytes)
                throw new ArgumentOutOfRangeHashLibException(MaximumOutputLengthExceeded);

            if (!Finalized)
            {
                Finish();
                Finalized = true;
            }
            
            if (RootHashDigest.Empty())
            {
                // Get root digest
                RootHashDigest = new byte[Blake2BHashSize];
                fixed (UInt64* statePtr = State)
                {
                    fixed (byte* RootHashDigestPtr = RootHashDigest)
                    {
                        Converters.le64_copy((IntPtr)statePtr, 0, (IntPtr)RootHashDigestPtr, 0,
                            RootHashDigest.Length);
                    }
                }
            }

            while (a_outputLength > 0)
            {
                if ((DigestPosition & (UInt64)(Blake2BHashSize - 1)) == 0)
                {
                    OutputConfig.Blake2BConfig.HashSize = ComputeStepLength();
                    OutputConfig.Blake2BTreeConfig.InnerHashSize = (byte)Blake2BHashSize;

                    Blake2XBBuffer = (new Blake2B(OutputConfig.Blake2BConfig, OutputConfig.Blake2BTreeConfig) as IHash)
                        .ComputeBytes(RootHashDigest).GetBytes();
                    OutputConfig.Blake2BTreeConfig.NodeOffset = OutputConfig.Blake2BTreeConfig.NodeOffset + 1;
                }

                blockOffset = DigestPosition & (UInt64)(Blake2BHashSize - 1);

                diff = (UInt64)Blake2XBBuffer.Length - blockOffset;

                count = Math.Min(a_outputLength, diff);

                Utils.Utils.Memmove(ref a_destination, Blake2XBBuffer, (Int32)count, (Int32)blockOffset, (Int32)a_destinationOffset);

                a_outputLength -= count;
                a_destinationOffset += count;
                DigestPosition += count;
            }

        }

        public Blake2XB(IBlake2XBConfig a_Blake2XBConfig)
        {
            Blake2XBConfig = a_Blake2XBConfig;

            // Create root hash config.
            RootConfig = new Blake2XBConfig();

            RootConfig.Blake2BConfig = Blake2XBConfig.Blake2BConfig;

            if (RootConfig.Blake2BConfig == null)
                RootConfig.Blake2BConfig = new Blake2BConfig();
            else
            {
                RootConfig.Blake2BConfig.Key = Blake2XBConfig.Blake2BConfig.Key;
                RootConfig.Blake2BConfig.Salt = Blake2XBConfig.Blake2BConfig.Salt;
                RootConfig.Blake2BConfig.Personalisation = Blake2XBConfig.Blake2BConfig.Personalisation;
            }

            RootConfig.Blake2BTreeConfig = Blake2XBConfig.Blake2BTreeConfig;

            if (RootConfig.Blake2BTreeConfig == null)
            {
                RootConfig.Blake2BTreeConfig = new Blake2BTreeConfig();
                RootConfig.Blake2BTreeConfig.FanOut = 1;
                RootConfig.Blake2BTreeConfig.MaxDepth = 1;

                RootConfig.Blake2BTreeConfig.LeafSize = 0;
                RootConfig.Blake2BTreeConfig.NodeOffset = 0;
                RootConfig.Blake2BTreeConfig.NodeDepth = 0;
                RootConfig.Blake2BTreeConfig.InnerHashSize = 0;
                RootConfig.Blake2BTreeConfig.IsLastNode = false;
            }

            // Create initial config for output hashes.
            OutputConfig = new Blake2XBConfig();

            OutputConfig.Blake2BConfig = new Blake2BConfig();
            OutputConfig.Blake2BConfig.Salt = RootConfig.Blake2BConfig.Salt;
            OutputConfig.Blake2BConfig.Personalisation = RootConfig.Blake2BConfig.Personalisation;

            OutputConfig.Blake2BTreeConfig = new Blake2BTreeConfig();

            // Blake 2B Configs
            Config = RootConfig.Blake2BConfig;
            TreeConfig = RootConfig.Blake2BTreeConfig;
            HashSize = Config.HashSize;

            Blake2XBBuffer = new byte[Blake2BHashSize];
        }

        public override void Initialize()
        {
            UInt64 xofSizeInBytes = XOFSizeInBits >> 3;

            RootConfig.Blake2BTreeConfig.NodeOffset = NodeOffsetWithXOFDigestLength(xofSizeInBytes);

            OutputConfig.Blake2BTreeConfig.NodeOffset = NodeOffsetWithXOFDigestLength(xofSizeInBytes);

            RootHashDigest = null;
            DigestPosition = 0;
            Finalized = false;
            ArrayUtils.ZeroFill(ref Blake2XBBuffer);

            base.Initialize();
        } // end function Initialize

        public override IHash Clone()
        {
            // Xof Cloning
            IXOF Xof = (new Blake2XB(Blake2XBConfig) as IXOF);
            Xof.XOFSizeInBits = (this as IXOF).XOFSizeInBits;

            // Blake2XB Cloning
            Blake2XB HashInstance = (Xof as Blake2XB);
            HashInstance.Blake2XBConfig = Blake2XBConfig.Clone();
            HashInstance.DigestPosition = DigestPosition;
            HashInstance.RootConfig = RootConfig.Clone();
            HashInstance.OutputConfig = OutputConfig.Clone();

            HashInstance.RootHashDigest = RootHashDigest.DeepCopy();
            HashInstance.Blake2XBBuffer = Blake2XBBuffer.DeepCopy();

            HashInstance.Finalized = Finalized;

            // Internal Blake2B Cloning
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

        public override void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            if (Finalized)
                throw new InvalidOperationHashLibException(String.Format(WritetoXofAfterReadError, Name));

            base.TransformBytes(a_data, a_index, a_length);
        }

        public override IHashResult TransformFinal()
        {
            byte[] buffer = GetResult();

            Initialize();

            return new HashResult(buffer);
        }

        private IXOF SetXOFSizeInBitsInternal(UInt64 a_XofSizeInBits)
        {
            UInt64 _xofSizeInBytes;

            _xofSizeInBytes = a_XofSizeInBits >> 3;
            if (((a_XofSizeInBits & 0x7) != 0) || (_xofSizeInBytes < 1) ||
                (_xofSizeInBytes > (UInt64)UnknownDigestLengthInBytes))
                throw new ArgumentInvalidHashLibException(
                    String.Format(InvalidXOFSize, 1, (UInt64)UnknownDigestLengthInBytes));

            xofSizeInBits = a_XofSizeInBits;

            return this;
        }

        private UInt64 NodeOffsetWithXOFDigestLength(UInt64 a_XOFSizeInBytes)
        {
            return ((UInt64)a_XOFSizeInBytes << 32);
        }

        private Int32 ComputeStepLength()
        {
            UInt64 xofSizeInBytes, diff;

            xofSizeInBytes = XOFSizeInBits >> 3;
            diff = xofSizeInBytes - DigestPosition;

            if (xofSizeInBytes == (UInt64)UnknownDigestLengthInBytes)
                return Blake2BHashSize;

            return (Int32)Math.Min((UInt64)Blake2BHashSize, diff);
        }

        private byte[] GetResult()
        {
            UInt64 xofSizeInBytes = XOFSizeInBits >> 3;

            byte[] result = new byte[xofSizeInBytes];

            DoOutput(ref result, 0, xofSizeInBytes);

            return result;
        }

    } // end class Blake2XB

    internal sealed class Blake2BMACNotBuildInAdapter : Hash, IBlake2BMACNotBuildIn, ICryptoNotBuildIn
    {
        private IHash hash = null;

        private byte[] key = null;
        public byte[] Key
        {
            get => key;
            set => key = value;
        }

        ~Blake2BMACNotBuildInAdapter()
        {
            Clear();
        }

        public override IHash Clone()
        {
            Blake2BMACNotBuildInAdapter HashInstance = new Blake2BMACNotBuildInAdapter(hash, Key);

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

        public static IBlake2BMAC CreateBlake2BMAC(byte[] a_Blake2BKey, byte[] a_Salt, byte[] a_Personalisation, Int32 a_OutputLengthInBits)
        {
            IBlake2BConfig config = new Blake2BConfig(a_OutputLengthInBits >> 3);

            config.Key = a_Blake2BKey.DeepCopy();
            config.Salt = a_Salt.DeepCopy();
            config.Personalisation = a_Personalisation.DeepCopy();

            return new Blake2BMACNotBuildInAdapter(new Blake2B(config, null), a_Blake2BKey);
        }

        private Blake2BMACNotBuildInAdapter(IHash a_Hash, byte[] a_Blake2BKey)
            : base(a_Hash?.HashSize ?? -1, a_Hash?.BlockSize ?? -1)
        {
            Key = a_Blake2BKey.DeepCopy();

            hash = a_Hash?.Clone();
        }

    } // end class Blake2BMACNotBuildInAdapter

}
