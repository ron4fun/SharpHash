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
using SharpHash.Crypto;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.KDF
{
    internal static class Global
    {
        public static readonly string InvalidOutputByteCount = "\"(ByteCount)\" Argument Less Than \"{0}\".";
        public static readonly string BlockInstanceNotInitialized = "Block Instance not Initialized";
        public static readonly string InputLengthInvalid = "Input Length \"{0}\" is not Equal to BlockSize \"{1}\"";
        public static readonly string LanesTooSmall = "Lanes Must be Greater Than \"{0}\"";
        public static readonly string LanesTooBig = "Lanes Must be Less Than \"{0}\"";
        public static readonly string MemoryTooSmall = "Memory is Less Than: \"{0}\", Expected \"{1}\"";
        public static readonly string IterationsTooSmall = "Iterations is Less Than: \"{0}\"";
        public static readonly string Argon2ParameterBuilderNotInitialized = "Argon2 Parameter Builder Not Initialized";
    } // end class Global

    /// <summary>
    /// Argon2 PBKDF - Based on the results of https://password-hashing.net/
    /// and https://www.ietf.org/archive/id/draft-irtf-cfrg-argon2-03.txt
    /// </summary>
    internal abstract class PBKDF_Argon2NotBuildInAdapter : Base.KDF, IPBKDF_Argon2, IPBKDF_Argon2NotBuildIn
    {
        private const Int32 ARGON2_BLOCK_SIZE = 1024;
        private const Int32 ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

        private const Int32 ARGON2_ADDRESSES_IN_BLOCK = 128;

        private const Int32 ARGON2_PREHASH_DIGEST_LENGTH = 64;
        private const Int32 ARGON2_PREHASH_SEED_LENGTH = 72;

        private const Int32 ARGON2_SYNC_POINTS = 4;

        // Minimum and maximum number of lanes (degree of parallelism)
        private const Int32 MIN_PARALLELISM = 1;

        private const Int32 MAX_PARALLELISM = 16777216;

        // Minimum digest size in bytes
        private const Int32 MIN_OUTLEN = 4;

        // Minimum and maximum number of passes
        private const Int32 MIN_ITERATIONS = 1;

        private struct Block
        {
            public const Int32 SIZE = ARGON2_QWORDS_IN_BLOCK;

            // 128 * 8 Byte QWords
            public UInt64[] v;

            public bool Initialized;

            private Block(UInt64[] _v, bool _Initialized)
            {
                v = new UInt64[0];
                if (!(_v == null || _v.Length == 0))
                {
                    v = new UInt64[_v.Length];
                    Utils.Utils.Memcopy(ref v, _v, _v.Length);
                } //

                Initialized = _Initialized;
            } //

            //private void CheckAreBlocksInitialized(Block[] a_Blocks);
            //private void CopyBlock(Block a_Other);
            //private void Xor(Block a_B1, Block a_B2);
            //private void XorWith(Block a_Other);

            //public static Block CreateBlock();

            //public void Clear();
            //public void Xor(Block a_B1, Block a_B2, Block a_B3);
            //public void FromBytes(byte[] a_Input);

            //public byte[] ToBytes();
            //public string ToString();
            public Block Clone()
            {
                return new Block
                {
                    v = new UInt64[0],
                    Initialized = true
                };
            } //
        }; // end Block

        private struct Position
        {
            public Int32 Pass, Lane, Slice, Index;
        };

        private struct TFillBlock
        {
            public Block R { get; }
            public Block Z { get; }
            public Block AddressBlock { get; }
            public Block ZeroBlock { get; }
            public Block InputBlock { get; }
        };

        private Block[] Memory;
        private Int32 SegmentLength, LaneLength;
        private IArgon2Parameters Parameters = null;
        private byte[] Password, Result;

        /// <summary>
        /// Initialise the <see cref="PBKDF_Argon2NotBuildInAdapter" />
        /// from the password and parameters.
        /// </summary>
        /// <param name="a_Password">
        /// the password to use.
        /// </param>
        /// <param name="a_Parameters">
        /// Argon2 configuration.
        /// </param>
        public PBKDF_Argon2NotBuildInAdapter(byte[] a_Password, IArgon2Parameters a_Parameters)
        {
        } // end cctr

        private void InitializeMemory(Int32 a_MemoryBlocks)
        {
            Memory = new Block[a_MemoryBlocks];
            for (Int32 i = 0; i < Memory.Length; i++)
                Memory[i] = new Block();
        } //

        private void DoInit(IArgon2Parameters a_Parameters)
        {
            Int32 MemoryBlocks;

            // 2. Align memory size
            // Minimum memoryBlocks = 8L blocks, where L is the number of lanes */
            MemoryBlocks = a_Parameters.Memory;

            if (MemoryBlocks < (2 * ARGON2_SYNC_POINTS * a_Parameters.Lanes))
                MemoryBlocks = 2 * ARGON2_SYNC_POINTS * a_Parameters.Lanes;

            SegmentLength = MemoryBlocks / (Parameters.Lanes * ARGON2_SYNC_POINTS);
            LaneLength = SegmentLength * ARGON2_SYNC_POINTS;

            // Ensure that all segments have equal length
            MemoryBlocks = SegmentLength * (a_Parameters.Lanes * ARGON2_SYNC_POINTS);

            InitializeMemory(MemoryBlocks);
        } //

        private void Reset()
        {
            // Reset memory.
            for (Int32 i = 0; i < Memory.Length; i++)
            {
                //Memory[i].Clear();
                Memory[i] = new Block();
            } //

            Memory = null;
            Utils.Utils.Memset(ref Result, 0, Result.Length);
            DoInit(Parameters);
        } //

        private void fBlaMka(Block a_Block, Int32 a_x, Int32 a_y)
        {
            UInt32 Lm = 0xFFFFFFFF;
            UInt64 Lxy = (a_Block.v[a_x] & Lm) * (a_Block.v[a_y] & Lm);

            a_Block.v[a_x] = a_Block.v[a_x] + a_Block.v[a_y] + (2 * Lxy);
        } //

        private void Rotr64(Block a_Block, Int32 a_v, Int32 a_w, Int32 a_c)
        {
            UInt64 Ltemp = a_Block.v[a_v] ^ a_Block.v[a_w];
            a_Block.v[a_v] = Bits.RotateRight64(Ltemp, a_c);
        } //

        private void F(Block a_Block, Int32 a_a, Int32 a_b, Int32 a_c, Int32 a_d)
        {
            fBlaMka(a_Block, a_a, a_b);
            Rotr64(a_Block, a_d, a_a, 32);

            fBlaMka(a_Block, a_c, a_d);
            Rotr64(a_Block, a_b, a_c, 24);

            fBlaMka(a_Block, a_a, a_b);
            Rotr64(a_Block, a_d, a_a, 16);

            fBlaMka(a_Block, a_c, a_d);
            Rotr64(a_Block, a_b, a_c, 63);
        } //

        private void RoundFunction(Block a_Block, Int32 a_v0, Int32 a_v1, Int32 a_v2, Int32 a_v3, Int32 a_v4, Int32 a_v5, Int32 a_v6,
            Int32 a_v7, Int32 a_v8, Int32 a_v9, Int32 a_v10, Int32 a_v11, Int32 a_v12, Int32 a_v13, Int32 a_v14, Int32 a_v15)
        {
            F(a_Block, a_v0, a_v4, a_v8, a_v12);
            F(a_Block, a_v1, a_v5, a_v9, a_v13);
            F(a_Block, a_v2, a_v6, a_v10, a_v14);
            F(a_Block, a_v3, a_v7, a_v11, a_v15);

            F(a_Block, a_v0, a_v5, a_v10, a_v15);
            F(a_Block, a_v1, a_v6, a_v11, a_v12);
            F(a_Block, a_v2, a_v7, a_v8, a_v13);
            F(a_Block, a_v3, a_v4, a_v9, a_v14);
        } //

        private void FillBlock(Block a_x, Block a_y, Block a_CurrentBlock, bool a_WithXor)
        {
            Block R, Z;
            Int32 i;

            R = new Block();
            Z = new Block();

            //R.Xor(a_x, a_y);
            Z = R.Clone();

            for (i = 0; i < 8; i++)
            {
                RoundFunction(Z, 16 * i, 16 * i + 1, 16 * i + 2, 16 * i + 3, 16 * i + 4,
                  16 * i + 5, 16 * i + 6, 16 * i + 7, 16 * i + 8, 16 * i + 9, 16 * i + 10,
                  16 * i + 11, 16 * i + 12, 16 * i + 13, 16 * i + 14, 16 * i + 15);
            } //

            for (i = 0; i < 8; i++)
            {
                RoundFunction(Z, 2 * i, 2 * i + 1, 2 * i + 16, 2 * i + 17, 2 * i + 32,
                  2 * i + 33, 2 * i + 48, 2 * i + 49, 2 * i + 64, 2 * i + 65, 2 * i + 80,
                  2 * i + 81, 2 * i + 96, 2 * i + 97, 2 * i + 112, 2 * i + 113);
            } //

            if (a_WithXor) ;
            //a_CurrentBlock.Xor(R, Z, a_CurrentBlock);
            else;
            // a_CurrentBlock.Xor(R, Z);
        } //

        private static void ValidatePBKDF_Argon2Inputs(IArgon2Parameters a_Argon2Parameters)
        {
            if (a_Argon2Parameters == null)
                throw new ArgumentNilHashLibException(Global.Argon2ParameterBuilderNotInitialized);
        } //

        private static void AddIntToLittleEndian(IHash a_Hash, Int32 a_n)
        {
            a_Hash.TransformBytes(Converters.ReadUInt32AsBytesLE((UInt32)a_n));
        } //

        private static void AddByteString(IHash a_Hash, byte[] a_Octets)
        {
            if (!(a_Octets == null || a_Octets.Length == 0))
            {
                AddIntToLittleEndian(a_Hash, a_Octets.Length);
                a_Hash.TransformBytes(a_Octets, 0, a_Octets.Length);
            } //
            else
                AddIntToLittleEndian(a_Hash, 0);
        } //

        //private static IHash MakeBlake2BInstanceAndInitialize(Int32 a_HashSize)
        //{
        //    var result = TBlake2B(TBlake2BConfig(a_HashSize) as IBlake2BConfig);
        //    result.Initialize();
        //} //

        private static Int32 GetStartingIndex(Position a_Position)
        {
            if ((a_Position.Pass == 0) && (a_Position.Slice == 0)) return 2; // we have already generated the first two blocks
            return 0;
        } //
    } // end class PBKDF_Argon2NotBuildInAdapter

    internal abstract class Argon2ParametersBuilder : IArgon2ParametersBuilder
    {
        private const Int32 DEFAULT_ITERATIONS = 3;
        private const Int32 DEFAULT_MEMORY_COST = 12;
        private const Int32 DEFAULT_LANES = 1;
        private const Argon2Type DEFAULT_TYPE = Argon2Type.a2tARGON2_i;
        private const Argon2Version DEFAULT_VERSION = Argon2Version.a2vARGON2_VERSION_13;

        private byte[] Salt, Secret, Additional;
        private Int32 Iterations, Memory, Lanes;
        private Argon2Type Type;
        private Argon2Version Version;

        protected Argon2ParametersBuilder(Argon2Type a_Type, byte[] a_Salt, byte[] a_Secret, byte[] a_Additional,
            Int32 a_Iterations, Int32 a_Memory, Int32 a_Lanes, Argon2Version a_Version)
        {
            Salt = new byte[a_Salt?.Length ?? 0];
            if (!(a_Salt == null || a_Salt.Length == 0))
                Utils.Utils.Memcopy(ref Salt, a_Salt, a_Salt.Length);

            Secret = new byte[a_Secret?.Length ?? 0];
            if (!(a_Secret == null || a_Secret.Length == 0))
                Utils.Utils.Memcopy(ref Secret, a_Secret, a_Secret.Length);

            Additional = new byte[a_Additional?.Length ?? 0];
            if (!(a_Additional == null || a_Additional.Length == 0))
                Utils.Utils.Memcopy(ref Additional, a_Additional, a_Additional.Length);

            Iterations = a_Iterations;
            Memory = a_Memory;
            Lanes = a_Lanes;
            Type = a_Type;
            Version = a_Version;
        } // end cctr

        protected Argon2ParametersBuilder(Argon2Type a_Type)
        {
            Lanes = DEFAULT_LANES;
            Memory = 1 << DEFAULT_MEMORY_COST;
            Iterations = DEFAULT_ITERATIONS;
            Type = a_Type;
            Version = DEFAULT_VERSION;
        } //

        ~Argon2ParametersBuilder()
        {
            Clear();
        } //

        public abstract IArgon2ParametersBuilder Build();

        public void Clear()
        {
            Utils.Utils.Memset(ref Salt, 0);
            Utils.Utils.Memset(ref Secret, 0);
            Utils.Utils.Memset(ref Additional, 0);
        }

        public IArgon2ParametersBuilder WithAdditional(byte[] a_Additional)
        {
            Additional = new byte[a_Additional?.Length ?? 0];
            if (!(a_Additional == null || a_Additional.Length == 0))
                Utils.Utils.Memcopy(ref Additional, a_Additional, a_Additional.Length);

            return this as IArgon2ParametersBuilder;
        } //

        public IArgon2ParametersBuilder WithIterations(int a_Iterations)
        {
            Iterations = a_Iterations;
            return this as IArgon2ParametersBuilder;
        } //

        public IArgon2ParametersBuilder WithMemoryAsKB(int a_Memory)
        {
            Memory = a_Memory;
            return this as IArgon2ParametersBuilder;
        } //

        public IArgon2ParametersBuilder WithMemoryPowOfTwo(int a_Memory)
        {
            Memory = 1 << a_Memory;
            return this as IArgon2ParametersBuilder;
        } //

        public IArgon2ParametersBuilder WithParallelism(int a_Parallelism)
        {
            Lanes = a_Parallelism;
            return this as IArgon2ParametersBuilder;
        } //

        public IArgon2ParametersBuilder WithSalt(byte[] a_Salt)
        {
            Salt = new byte[a_Salt?.Length ?? 0];
            if (!(a_Salt == null || a_Salt.Length == 0))
                Utils.Utils.Memcopy(ref Salt, a_Salt, a_Salt.Length);

            return this as IArgon2ParametersBuilder;
        } //

        public IArgon2ParametersBuilder WithSecret(byte[] a_Secret)
        {
            Secret = new byte[a_Secret?.Length ?? 0];
            if (!(a_Secret == null || a_Secret.Length == 0))
                Utils.Utils.Memcopy(ref Secret, a_Secret, a_Secret.Length);

            return this as IArgon2ParametersBuilder;
        } //

        public IArgon2ParametersBuilder WithVersion(Argon2Version a_Version)
        {
            Version = a_Version;
            return this as IArgon2ParametersBuilder;
        } //
    } // end class Argon2ParametersBuilder

    internal sealed class Argon2Parameters // : IArgon2Parameters
    {
        private byte[] Salt, Secret, Additional;
        private Int32 Iterations, Memory, Lanes;
        private Argon2Type Type;
        private Argon2Version Version;

        public Argon2Parameters()
        {
        } // end cctr
    } // end class Argon2Parameters

    internal sealed class Argon2iParametersBuilder : Argon2ParametersBuilder
    {
        private Argon2iParametersBuilder()
            : base(Argon2Type.a2tARGON2_i)
        {
        } // end cctr

        public override IArgon2ParametersBuilder Build()
        {
            var builder = new Argon2iParametersBuilder();
            return builder as IArgon2ParametersBuilder; ;
        }
    } // end class Argon2iParametersBuilder

    internal sealed class Argon2dParametersBuilder : Argon2ParametersBuilder
    {
        private Argon2dParametersBuilder()
            : base(Argon2Type.a2tARGON2_d)
        {
        } // end cctr

        public override IArgon2ParametersBuilder Build()
        {
            var builder = new Argon2dParametersBuilder();
            return builder as IArgon2ParametersBuilder; ;
        }
    } // end class Argon2dParametersBuilder

    internal sealed class Argon2idParametersBuilder : Argon2ParametersBuilder
    {
        private Argon2idParametersBuilder()
            : base(Argon2Type.a2tARGON2_id)
        {
        } // end cctr

        public override IArgon2ParametersBuilder Build()
        {
            var builder = new Argon2idParametersBuilder();
            return builder as IArgon2ParametersBuilder; ;
        }
    } // end class Argon2idParametersBuilder
}