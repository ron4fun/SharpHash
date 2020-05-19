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

using SharpHash.Crypto;
using SharpHash.Crypto.Blake2BConfigurations;
using SharpHash.Interfaces;
using SharpHash.Interfaces.IBlake2BConfigurations;
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
    internal sealed class PBKDF_Argon2NotBuildInAdapter : Base.KDF, IPBKDF_Argon2, IPBKDF_Argon2NotBuildIn
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
                v = _v.DeepCopy();

                Initialized = _Initialized;
            } //

            private void CheckAreBlocksInitialized(Block[] a_Blocks)
            {
                foreach (Block block in a_Blocks)
                {
                    if (!block.Initialized)
                        throw new ArgumentNilHashLibException(Global.BlockInstanceNotInitialized);
                }
            } // end function CheckAreBlocksInitialized

            public void CopyBlock(Block a_Other)
            {
                CheckAreBlocksInitialized(new Block[] { this, a_Other });
                v = a_Other.v.DeepCopy();
            } // end function CopyBlock

            public void Xor(Block a_B1, Block a_B2)
            {
                Int32 LIdx;

                CheckAreBlocksInitialized(new Block[] { this, a_B1, a_B2 });
                for (LIdx = 0; LIdx < SIZE; LIdx++)
                    v[LIdx] = a_B1.v[LIdx] ^ a_B2.v[LIdx];

            } // end function Xor

            public void XorWith(Block a_Other)
            {
                Int32 LIdx;

                CheckAreBlocksInitialized(new Block[] { this, a_Other });
                for (LIdx = 0; LIdx < v.Length; LIdx++)
                    v[LIdx] = v[LIdx] ^ a_Other.v[LIdx];

            } // end function XorWith

            public static Block CreateBlock()
            {
                Block result = new Block();

                result.v = new UInt64[SIZE];
                result.Initialized = true;

                return result;
            } // end funtion CreateBlock

            public Block Clear()
            {
                CheckAreBlocksInitialized(new Block[] { this });

                ArrayUtils.ZeroFill(ref v);

                return this;
            } // end function Clear

            public void Xor(Block a_B1, Block a_B2, Block a_B3)
            {
                Int32 LIdx;

                CheckAreBlocksInitialized(new Block[] { this, a_B1, a_B2, a_B3 });
                for (LIdx = 0; LIdx < SIZE; LIdx++)
                    v[LIdx] = a_B1.v[LIdx] ^ a_B2.v[LIdx] ^ a_B3.v[LIdx];

            } // end function Xor

            public unsafe void FromBytes(byte[] a_Input)
            {
                Int32 LIdx;

                CheckAreBlocksInitialized(new Block[] { this });
                if (a_Input.Length != ARGON2_BLOCK_SIZE)
                    throw new ArgumentHashLibException(
                        String.Format(Global.InputLengthInvalid, a_Input.Length, ARGON2_BLOCK_SIZE));

                fixed (byte* LPtrInput = a_Input)
                {
                    for (LIdx = 0; LIdx < SIZE; LIdx++)
                        v[LIdx] = Converters.ReadBytesAsUInt64LE((IntPtr)LPtrInput, LIdx * 8);
                }

            } // end function FromBytes

            public byte[] ToBytes()
            {
                Int32 LIdx;

                CheckAreBlocksInitialized(new Block[] { this });

                byte[] result = new byte[ARGON2_BLOCK_SIZE];
                for (LIdx = 0; LIdx < SIZE; LIdx++)
                    Converters.ReadUInt64AsBytesLE(v[LIdx], ref result, LIdx * 8);

                return result;
            } // end function ToBytes

            public override string ToString()
            {
                Int32 LIdx;

                CheckAreBlocksInitialized(new Block[] { this });

                string result = "";
                for (LIdx = 0; LIdx < SIZE; LIdx++)
                    result = result + Converters.ConvertBytesToHexString(
                        Converters.ReadUInt64AsBytesLE(v[LIdx]), false);

                return result;
            } // end function ToString

            public Block Clone()
            {
                return new Block
                {
                    v = v.DeepCopy(),
                    Initialized = Initialized
                };
            } // end function Clone

        }; // end Block

        private struct Position
        {
            public Int32 Pass { get; set; }
            public Int32 Lane { get; set; }
            public Int32 Slice { get; set; }
            public Int32 Index { get; set; }

            public static Position CreatePosition()
            {
                return new Position();
            } // end function CreatePosition

            public void Update(Int32 a_Pass, Int32 a_Lane, Int32 a_Slice, Int32 a_Index)
            {
                Pass = a_Pass;
                Lane = a_Lane;
                Slice = a_Slice;
                Index = a_Index;
            } // end function Update

        } // end struct Position

        private struct TFillBlock
        {
            public Block R, Z, AddressBlock, ZeroBlock, InputBlock;

            public static void BlaMka(ref Block a_Block, Int32 a_x, Int32 a_y)
            {
                UInt32 Lm = 0xFFFFFFFF;
                UInt64 Lxy = (a_Block.v[a_x] & Lm) * (a_Block.v[a_y] & Lm);

                a_Block.v[a_x] = a_Block.v[a_x] + a_Block.v[a_y] + (2 * Lxy);
            }  // end function BlaMka 

            public static void Rotr64(ref Block a_Block, Int32 a_v, Int32 a_w, Int32 a_c)
            {
                UInt64 LTemp = a_Block.v[a_v] ^ a_Block.v[a_w];
                a_Block.v[a_v] = Bits.RotateRight64(LTemp, a_c);
            } // end function Rotr64

            public static void F(ref Block a_Block, Int32 a_a, Int32 a_b, Int32 a_c, Int32 a_d)
            {
                BlaMka(ref a_Block, a_a, a_b);
                Rotr64(ref a_Block, a_d, a_a, 32);

                BlaMka(ref a_Block, a_c, a_d);
                Rotr64(ref a_Block, a_b, a_c, 24);

                BlaMka(ref a_Block, a_a, a_b);
                Rotr64(ref a_Block, a_d, a_a, 16);

                BlaMka(ref a_Block, a_c, a_d);
                Rotr64(ref a_Block, a_b, a_c, 63);
            }  // end function F

            public static void RoundFunction(ref Block a_Block, Int32 a_v0, Int32 a_v1, Int32 a_v2, Int32 a_v3,
                Int32 a_v4, Int32 a_v5, Int32 a_v6, Int32 a_v7, Int32 a_v8, Int32 a_v9, Int32 a_v10,
                Int32 a_v11, Int32 a_v12, Int32 a_v13, Int32 a_v14, Int32 a_v15)
            {
                F(ref a_Block, a_v0, a_v4, a_v8, a_v12);
                F(ref a_Block, a_v1, a_v5, a_v9, a_v13);
                F(ref a_Block, a_v2, a_v6, a_v10, a_v14);
                F(ref a_Block, a_v3, a_v7, a_v11, a_v15);

                F(ref a_Block, a_v0, a_v5, a_v10, a_v15);
                F(ref a_Block, a_v1, a_v6, a_v11, a_v12);
                F(ref a_Block, a_v2, a_v7, a_v8, a_v13);
                F(ref a_Block, a_v3, a_v4, a_v9, a_v14);
            } // end function RoundFunction

            private void ApplyBlake()
            {
                Int32 Li, Li16, Li2;

                /* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , 
                 * then (16,17,..31)... finally (112,113,...127) */

                for (Li = 0; Li < 8; Li++)
                {
                    Li16 = 16 * Li;
                    RoundFunction(ref Z, Li16, Li16 + 1, Li16 + 2, Li16 + 3, Li16 + 4, Li16 + 5,
                      Li16 + 6, Li16 + 7, Li16 + 8, Li16 + 9, Li16 + 10, Li16 + 11, Li16 + 12,
                      Li16 + 13, Li16 + 14, Li16 + 15);
                }

                /* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), 
                then (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */

                for (Li = 0; Li < 8; Li++)
                {
                    Li2 = 2 * Li;
                    RoundFunction(ref Z, Li2, Li2 + 1, Li2 + 16, Li2 + 17, Li2 + 32, Li2 + 33,
                      Li2 + 48, Li2 + 49, Li2 + 64, Li2 + 65, Li2 + 80, Li2 + 81, Li2 + 96,
                      Li2 + 97, Li2 + 112, Li2 + 113);
                }
            } // end function ApplyBlake

            public static TFillBlock CreateFillBlock()
            {
                TFillBlock result = new TFillBlock();

                result.R = Block.CreateBlock();
                result.Z = Block.CreateBlock();
                result.AddressBlock = Block.CreateBlock();
                result.ZeroBlock = Block.CreateBlock();
                result.InputBlock = Block.CreateBlock();

                return result;
            } // end function CreateFillBlock

            public void FillBlock(Block a_x, Block a_y, ref Block a_CurrentBlock, bool a_WithXor)
            {
                R.Xor(a_x, a_y);
                Z.CopyBlock(R);

                ApplyBlake();

                if (a_WithXor)
                    a_CurrentBlock.Xor(R, Z, a_CurrentBlock);
                else
                    a_CurrentBlock.Xor(R, Z);

            } // end function FillBlock

        }; // end struct TFillBlock

        private struct DataContainer
        {
            public Position Position;
        }; // end struct DataContainer

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
            ValidatePBKDF_Argon2Inputs(a_Parameters);

            Password = a_Password.DeepCopy();
            Parameters = a_Parameters;

            if (Parameters.Lanes < MIN_PARALLELISM)
                throw new ArgumentInvalidHashLibException(
                    String.Format(Global.LanesTooSmall, MIN_PARALLELISM));
            else if (Parameters.Lanes > MAX_PARALLELISM)
                throw new ArgumentInvalidHashLibException(
                    String.Format(Global.LanesTooBig, MAX_PARALLELISM));
            else if (Parameters.Memory < (2 * Parameters.Lanes))
                throw new ArgumentInvalidHashLibException(
                    String.Format(Global.MemoryTooSmall, 2 * Parameters.Lanes, 2 * Parameters.Lanes));
            else if (Parameters.Iterations < MIN_ITERATIONS)
                throw new ArgumentInvalidHashLibException(
                    String.Format(Global.IterationsTooSmall, MIN_ITERATIONS));
           
            DoInit(a_Parameters);
        } // end cctr

        ~PBKDF_Argon2NotBuildInAdapter()
        {
            Clear();
        } //

        public override byte[] GetBytes(Int32 a_ByteCount)
        {
            if (a_ByteCount <= MIN_OUTLEN)
                throw new ArgumentHashLibException(
                    String.Format(Global.InvalidOutputByteCount, MIN_OUTLEN));

            Initialize(Password, a_ByteCount);
            Position LPosition = Position.CreatePosition();
            DataContainer LPtrDataContainer = new DataContainer();
            try
            {
                LPtrDataContainer.Position = LPosition;
                DoParallelFillMemoryBlocks(ref LPtrDataContainer);
            }
            finally
            {
                // Dispose
                LPtrDataContainer = new DataContainer();
            }

            Digest(a_ByteCount);

            byte[] result = new byte[a_ByteCount];

            Utils.Utils.Memmove(ref result, Result, a_ByteCount * sizeof(byte));

            Reset();

            return result;
        }  // end function GetBytes

        public override void Clear()
        {
            ArrayUtils.ZeroFill(ref Password);
        } // end function Clear

        private byte[] InitialHash(IArgon2Parameters a_Parameters, Int32 a_OutputLength,
            byte[] a_Password)
        {
            IHash LBlake2B = MakeBlake2BInstanceAndInitialize(ARGON2_PREHASH_DIGEST_LENGTH);

            AddIntToLittleEndian(LBlake2B, a_Parameters.Lanes);
            AddIntToLittleEndian(LBlake2B, a_OutputLength);
            AddIntToLittleEndian(LBlake2B, a_Parameters.Memory);
            AddIntToLittleEndian(LBlake2B, a_Parameters.Iterations);
            AddIntToLittleEndian(LBlake2B, (Int32)a_Parameters.Version);
            AddIntToLittleEndian(LBlake2B, (Int32)a_Parameters.Type);

            AddByteString(LBlake2B, a_Password);
            AddByteString(LBlake2B, a_Parameters.Salt);
            AddByteString(LBlake2B, a_Parameters.Secret);
            AddByteString(LBlake2B, a_Parameters.Additional);

            return LBlake2B.TransformFinal().GetBytes();
        } // end function InitialHash

        private byte[] GetInitialHashLong(byte[] a_InitialHash, byte[] a_Appendix)
        {
            byte[] result = new byte[ARGON2_PREHASH_SEED_LENGTH];

            Utils.Utils.Memmove(ref result, a_InitialHash, ARGON2_PREHASH_DIGEST_LENGTH * sizeof(byte));

            Utils.Utils.Memmove(ref result, a_Appendix, 4 * sizeof(byte), 0, ARGON2_PREHASH_DIGEST_LENGTH);

            return result;
        } // end function GetInitialHashLong

        private byte[] Hash(byte[] a_Input, Int32 a_OutputLength)
        {
            byte[] LOutlenBytes, LOutBuffer;
            Int32 LBlake2BLength, Lr, LPosition, LIdx, LLastLength;
            IHash LBlake2B;

            byte[] result = new byte[a_OutputLength];
            LOutlenBytes = Converters.ReadUInt32AsBytesLE((UInt32)a_OutputLength);

            LBlake2BLength = 64;

            if (a_OutputLength <= LBlake2BLength)
            {
                LBlake2B = MakeBlake2BInstanceAndInitialize(a_OutputLength);

                LBlake2B.TransformBytes(LOutlenBytes, 0, LOutlenBytes.Length);
                LBlake2B.TransformBytes(a_Input, 0, a_Input.Length);
                result = LBlake2B.TransformFinal().GetBytes();
            } // end if
            else
            {
                LBlake2B = MakeBlake2BInstanceAndInitialize(LBlake2BLength);

                LOutBuffer = new byte[LBlake2BLength];

                // V1
                LBlake2B.TransformBytes(LOutlenBytes, 0, LOutlenBytes.Length);
                LBlake2B.TransformBytes(a_Input, 0, a_Input.Length);
                LOutBuffer = LBlake2B.TransformFinal().GetBytes();

                Utils.Utils.Memmove(ref result, LOutBuffer, (LBlake2BLength / 2) * sizeof(byte));

                Lr = ((a_OutputLength + 31) / 32) - 2;

                LPosition = LBlake2BLength / 2;

                LIdx = 2;

                while (LIdx <= Lr)
                {
                    // V2 to Vr
                    LBlake2B.TransformBytes(LOutBuffer, 0, LOutBuffer.Length);
                    LOutBuffer = LBlake2B.TransformFinal().GetBytes();

                    Utils.Utils.Memmove(ref result, LOutBuffer,
                        (LBlake2BLength / 2) * sizeof(byte), 0, LPosition);

                    LIdx++;
                    LPosition = LPosition + (LBlake2BLength / 2);
                }


                LLastLength = a_OutputLength - (32 * Lr);

                // Vr+1

                LBlake2B = MakeBlake2BInstanceAndInitialize(LLastLength);

                LBlake2B.TransformBytes(LOutBuffer, 0, LOutBuffer.Length);
                LOutBuffer = LBlake2B.TransformFinal().GetBytes();
                Utils.Utils.Memmove(ref result, LOutBuffer,
                    LLastLength * sizeof(byte), 0, LPosition);
            }

            return result;
        } // end function Hash

        private void Digest(Int32 a_OutputLength)
        {
            Int32 LIdx, LLastBlockInLane;
            byte[] FFinalBlockBytes;
            Block FFinalBlock;

            FFinalBlock = Memory[LaneLength - 1];

            // XOR the last blocks
            for (LIdx = 1; LIdx < Parameters.Lanes; LIdx++)
            {
                LLastBlockInLane = (LIdx * LaneLength) + (LaneLength - 1);
                FFinalBlock.XorWith(Memory[LLastBlockInLane]);
            }

            FFinalBlockBytes = FFinalBlock.ToBytes();

            Result = Hash(FFinalBlockBytes, a_OutputLength);
        } // end funtion Digest

        private void FillFirstBlocks(byte[] a_InitialHash)
        {
            byte[] LZeroBytes, LOneBytes, LInitialHashWithZeros, LInitialHashWithOnes, LBlockHashBytes;
            Int32 LIdx;

            LZeroBytes = new byte[] { 0, 0, 0, 0 };
            LOneBytes = new byte[] { 1, 0, 0, 0 };

            LInitialHashWithZeros = GetInitialHashLong(a_InitialHash, LZeroBytes);
            LInitialHashWithOnes = GetInitialHashLong(a_InitialHash, LOneBytes);

            for (LIdx = 0; LIdx < Parameters.Lanes; LIdx++)
            {
                Converters.ReadUInt32AsBytesLE((UInt32)LIdx, ref LInitialHashWithZeros, ARGON2_PREHASH_DIGEST_LENGTH + 4);
                Converters.ReadUInt32AsBytesLE((UInt32)LIdx, ref LInitialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH + 4);

                LBlockHashBytes = Hash(LInitialHashWithZeros, ARGON2_BLOCK_SIZE);
                Memory[LIdx * LaneLength].FromBytes(LBlockHashBytes);

                LBlockHashBytes = Hash(LInitialHashWithOnes, ARGON2_BLOCK_SIZE);
                Memory[(LIdx * LaneLength) + 1].FromBytes(LBlockHashBytes);
            } //
        } // end function FillFirstBlocks

        private bool IsDataIndependentAddressing(Position a_Position)
        {
            return (Parameters.Type == Argon2Type.a2tARGON2_i) ||
                ((Parameters.Type == Argon2Type.a2tARGON2_id) && (a_Position.Pass == 0)
                && (a_Position.Slice < (ARGON2_SYNC_POINTS / 2)));
        } // end function IsDataIndependentAddressing

        private void Initialize(byte[] a_Password, Int32 a_OutputLength)
        {
            byte[] LInitialHash = InitialHash(Parameters, a_OutputLength, a_Password);
            FillFirstBlocks(LInitialHash);
        } // end function Initialize

        private void FillSegment(Int32 a_Idx, Position a_Position)
        {
            Block LAddressBlock, LInputBlock, LZeroBlock, LPrevBlock, LRefBlock, LCurrentBlock;
            bool LDataIndependentAddressing, LWithXor;
            Int32 LStartingIndex, LCurrentOffset, LPrevOffset, LRefLane, LRefColumn;
            UInt64 LPseudoRandom;
            TFillBlock LFiller;

            // line below not really needed, just added to fix compiler hint
            a_Position.Lane = a_Idx;
            LFiller = TFillBlock.CreateFillBlock();
            LDataIndependentAddressing = IsDataIndependentAddressing(a_Position);
            LStartingIndex = GetStartingIndex(a_Position);
            LCurrentOffset = (a_Position.Lane * LaneLength) +
                (a_Position.Slice * SegmentLength) + LStartingIndex;
            LPrevOffset = GetPrevOffset(LCurrentOffset);

            LAddressBlock = new Block();
            LInputBlock = new Block();
            LZeroBlock = new Block();

            if (LDataIndependentAddressing)
            {
                LAddressBlock = LFiller.AddressBlock.Clear();
                LZeroBlock = LFiller.ZeroBlock.Clear();
                LInputBlock = LFiller.InputBlock.Clear();

                InitAddressBlocks(LFiller, a_Position, LZeroBlock, ref LInputBlock, ref LAddressBlock);
            }

            a_Position.Index = LStartingIndex;

            while (a_Position.Index < SegmentLength)
            {
                LPrevOffset = RotatePrevOffset(LCurrentOffset, LPrevOffset);

                LPseudoRandom = GetPseudoRandom(LFiller, a_Position, LAddressBlock,
                  LInputBlock, LZeroBlock, LPrevOffset, LDataIndependentAddressing);
                LRefLane = GetRefLane(a_Position, LPseudoRandom);
                LRefColumn = GetRefColumn(a_Position, LPseudoRandom, LRefLane == a_Position.Lane);

                // 2 Creating a new block
                LPrevBlock = Memory[LPrevOffset];
                LRefBlock = Memory[(((LaneLength) * LRefLane) + LRefColumn)];
                LCurrentBlock = Memory[LCurrentOffset];

                LWithXor = IsWithXor(a_Position);
                LFiller.FillBlock(LPrevBlock, LRefBlock, ref LCurrentBlock, LWithXor);

                a_Position.Index++;
                LCurrentOffset++;
                LPrevOffset++;
            } //

        } // end function FillSegment

        private void InitializeMemory(Int32 a_MemoryBlocks)
        {
            Memory = new Block[a_MemoryBlocks];
            for (Int32 i = 0; i < Memory.Length; i++)
                Memory[i] = Block.CreateBlock();
        } // end function InitializeMemory

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
        } // end function DoInit

        private void NextAddresses(TFillBlock a_Filler, Block a_ZeroBlock,
            Block a_InputBlock, ref Block a_AddressBlock)
        {
            a_InputBlock.v[6]++;
            a_Filler.FillBlock(a_ZeroBlock, a_InputBlock, ref a_AddressBlock, false);
            a_Filler.FillBlock(a_ZeroBlock, a_AddressBlock, ref a_AddressBlock, false);
        } // end function NextAddresses

        private void FillMemoryBlocks(Int32 a_Idx, ref DataContainer a_DataContainer)
        {
            Position LPosition = a_DataContainer.Position;
            FillSegment(a_Idx, LPosition);
        } // end function FillMemoryBlocks

        private void DoParallelFillMemoryBlocks(ref DataContainer a_DataContainer)
        {
            Int32 LIdx, LJdx, LKdx, LIterations, LLanes;

            LIterations = Parameters.Iterations;
            LLanes = Parameters.Lanes;

            for (LIdx = 0; LIdx < LIterations; LIdx++)
            {
                for (LJdx = 0; LJdx < ARGON2_SYNC_POINTS; LJdx++)
                {
                    for (LKdx = 0; LKdx < LLanes; LKdx++)
                    {
                        a_DataContainer.Position.Update(LIdx, LKdx, LJdx, 0);
                        FillMemoryBlocks(LKdx, ref a_DataContainer);
                    }
                }
            }
        } // end function DoParallelFillMemoryBlocks

        private void InitAddressBlocks(TFillBlock a_Filler, Position a_Position,
            Block a_ZeroBlock, ref Block a_InputBlock, ref Block a_AddressBlock)
        {
            a_InputBlock.v[0] = IntToUInt64(a_Position.Pass);
            a_InputBlock.v[1] = IntToUInt64(a_Position.Lane);
            a_InputBlock.v[2] = IntToUInt64(a_Position.Slice);
            a_InputBlock.v[3] = IntToUInt64(Memory.Length);
            a_InputBlock.v[4] = IntToUInt64(Parameters.Iterations);
            a_InputBlock.v[5] = IntToUInt64((Int32)Parameters.Type);

            if ((a_Position.Pass == 0) && (a_Position.Slice == 0))
                // Don't forget to generate the first block of addresses: */
                NextAddresses(a_Filler, a_ZeroBlock, a_InputBlock, ref a_AddressBlock);
        } // end function InitAddressBlocks

        private bool IsWithXor(Position a_Position)
        {
            return !((a_Position.Pass == 0) || (Parameters.Version == Argon2Version.a2vARGON2_VERSION_10));
        } // end function IsWithXor

        private Int32 GetPrevOffset(Int32 a_CurrentOffset)
        {
            if (a_CurrentOffset % LaneLength == 0)
                return a_CurrentOffset + LaneLength - 1;

            return a_CurrentOffset - 1;
        } // end function GetPrevOffset

        private Int32 RotatePrevOffset(Int32 a_CurrentOffset, Int32 a_PrevOffset)
        {
            if (a_CurrentOffset % LaneLength == 1)
                a_PrevOffset = a_CurrentOffset - 1;

            return a_PrevOffset;
        } // end function RotatePrevOffset

        private static UInt64 IntToUInt64(Int32 a_x)
        {
            return (UInt64)((a_x & (UInt32)0xFFFFFFFF));
        } // end function IntToUInt64

        private void Reset()
        {
            // Reset memory.
            for (Int32 i = 0; i < Memory.Length; i++)
            {
                Memory[i].Clear();
                Memory[i] = new Block();
            } //

            Memory = null;
            ArrayUtils.ZeroFill(ref Result);
        } // end function Reset

        private void fBlaMka(Block a_Block, Int32 a_x, Int32 a_y)
        {
            UInt32 Lm = 0xFFFFFFFF;
            UInt64 Lxy = (a_Block.v[a_x] & Lm) * (a_Block.v[a_y] & Lm);

            a_Block.v[a_x] = a_Block.v[a_x] + a_Block.v[a_y] + (2 * Lxy);
        } // end funcction fBlaMka

        private void Rotr64(Block a_Block, Int32 a_v, Int32 a_w, Int32 a_c)
        {
            UInt64 Ltemp = a_Block.v[a_v] ^ a_Block.v[a_w];
            a_Block.v[a_v] = Bits.RotateRight64(Ltemp, a_c);
        } // end function Rotr64

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
        } // end function F

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

        private UInt64 GetPseudoRandom(TFillBlock a_Filler, Position a_Position,
            Block a_AddressBlock, Block a_InputBlock, Block a_ZeroBlock, Int32 a_PrevOffset,
            bool a_DataIndependentAddressing)
        {
            if (a_DataIndependentAddressing)
            {
                if (a_Position.Index % ARGON2_ADDRESSES_IN_BLOCK == 0)
                    NextAddresses(a_Filler, a_ZeroBlock, a_InputBlock, ref a_AddressBlock);

                return a_AddressBlock.v[a_Position.Index % ARGON2_ADDRESSES_IN_BLOCK];
            }

            return Memory[a_PrevOffset].v[0];
        } // end function GetPseudoRandom

        private Int32 GetRefLane(Position a_Position, UInt64 a_PseudoRandom)
        {
            Int32 LRefLane = (Int32)((a_PseudoRandom >> 32) % (UInt64)Parameters.Lanes);

            if ((a_Position.Pass == 0) && (a_Position.Slice == 0))
                // Can not reference other lanes yet
                LRefLane = a_Position.Lane;

            return LRefLane;
        } // end function GetRefLane

        private Int32 GetRefColumn(Position a_Position, UInt64 a_PseudoRandom, bool a_SameLane)
        {
            Int32 LReferenceAreaSize, LStartPosition, LTemp;
            UInt64 LRelativePosition;

            if (a_Position.Pass == 0)
            {
                LStartPosition = 0;

                if (a_SameLane)
                {
                    // The same lane => add current segment
                    LReferenceAreaSize = ((a_Position.Slice) * SegmentLength) +
                      a_Position.Index - 1;
                }
                else
                {
                    if (a_Position.Index == 0)
                        LTemp = -1;
                    else
                        LTemp = 0;

                    LReferenceAreaSize = (a_Position.Slice * SegmentLength) + LTemp;
                }
            }
            else
            {
                LStartPosition = ((a_Position.Slice + 1) * SegmentLength) % LaneLength;

                if (a_SameLane)
                {
                    LReferenceAreaSize = LaneLength - SegmentLength + a_Position.Index - 1;
                }
                else
                {
                    if (a_Position.Index == 0)
                        LTemp = -1;
                    else
                        LTemp = 0;

                    LReferenceAreaSize = LaneLength - SegmentLength + LTemp;
                }
            }

            LRelativePosition = a_PseudoRandom & (UInt32)0xFFFFFFFF;
            LRelativePosition = (LRelativePosition * LRelativePosition) >> 32;
            LRelativePosition = (UInt64)LReferenceAreaSize - 1 -
        (UInt64)(((UInt64)LReferenceAreaSize * LRelativePosition) >> 32);

            return (Int32)(((UInt64)LStartPosition + LRelativePosition) % (UInt64)LaneLength);
        } // end function GetRefColumn

        private static void ValidatePBKDF_Argon2Inputs(IArgon2Parameters a_Argon2Parameters)
        {
            if (a_Argon2Parameters == null)
                throw new ArgumentNilHashLibException(Global.Argon2ParameterBuilderNotInitialized);
        } // end function ValidatePBKDF_Argon2Inputs

        private static void AddIntToLittleEndian(IHash a_Hash, Int32 a_n)
        {
            a_Hash.TransformBytes(Converters.ReadUInt32AsBytesLE((UInt32)a_n));
        } // end function AddIntToLittleEndian

        private static void AddByteString(IHash a_Hash, byte[] a_Octets)
        {
            if (!a_Octets.Empty())
            {
                AddIntToLittleEndian(a_Hash, a_Octets.Length);
                a_Hash.TransformBytes(a_Octets, 0, a_Octets.Length);
            } //
            else
                AddIntToLittleEndian(a_Hash, 0);
        } // end function AddByteString

        private static IHash MakeBlake2BInstanceAndInitialize(Int32 a_HashSize)
        {
            var result = new Blake2B(new Blake2BConfig(a_HashSize) as IBlake2BConfig);

            result.Initialize();

            return result;
        } // end function MakeBlake2BInstanceAndInitialize

        private static Int32 GetStartingIndex(Position a_Position)
        {
            if ((a_Position.Pass == 0) && (a_Position.Slice == 0)) return 2; // we have already generated the first two blocks
            return 0;
        } // end function GetStartingIndex

    } // end class PBKDF_Argon2NotBuildInAdapter

    public abstract class Argon2ParametersBuilder : IArgon2ParametersBuilder
    {
        private const Int32 DEFAULT_ITERATIONS = 3;
        private const Int32 DEFAULT_MEMORY_COST = 12;
        private const Int32 DEFAULT_LANES = 1;
        private const Argon2Type DEFAULT_TYPE = Argon2Type.a2tARGON2_i;
        private const Argon2Version DEFAULT_VERSION = Argon2Version.a2vARGON2_VERSION_13;

        public byte[] Salt, Secret, Additional;
        public Int32 Iterations, Memory, Lanes;
        public Argon2Type Type;
        public Argon2Version Version;

        protected Argon2ParametersBuilder(Argon2Type a_Type, byte[] a_Salt, byte[] a_Secret, byte[] a_Additional,
            Int32 a_Iterations, Int32 a_Memory, Int32 a_Lanes, Argon2Version a_Version)
        {
            Salt = a_Salt.DeepCopy();
            Secret = a_Secret.DeepCopy();
            Additional = a_Additional.DeepCopy();

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

        public IArgon2Parameters Build()
        {
            return new Argon2Parameters(Type, Salt, Secret, Additional,
                Iterations, Memory, Lanes, Version);
        }

        public void Clear()
        {
            ArrayUtils.ZeroFill(ref Salt);
            ArrayUtils.ZeroFill(ref Secret);
            ArrayUtils.ZeroFill(ref Additional);
        }

        public IArgon2ParametersBuilder WithAdditional(byte[] a_Additional)
        {
            Additional = a_Additional.DeepCopy();
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
            Salt = a_Salt.DeepCopy();
            return this as IArgon2ParametersBuilder;
        } //

        public IArgon2ParametersBuilder WithSecret(byte[] a_Secret)
        {
            Secret = a_Secret.DeepCopy();
            return this as IArgon2ParametersBuilder;
        } //

        public IArgon2ParametersBuilder WithVersion(Argon2Version a_Version)
        {
            Version = a_Version;
            return this as IArgon2ParametersBuilder;
        } //

    } // end class Argon2ParametersBuilder

    public sealed class Argon2Parameters : IArgon2Parameters
    {
        private byte[] salt;
        public byte[] Salt {
            get => salt;
            set => salt = value;
        }

        private byte[] secret;
        public byte[] Secret
        {
            get => secret;
            set => secret = value;
        }

        private byte[] additional;
        public byte[] Additional
        {
            get => additional;
            set => additional = value;
        }
        
        public Int32 Iterations { get; set; }
        public Int32 Memory { get; set; }
        public Int32 Lanes { get; set; }
        public Argon2Type Type { get; set; }
        public Argon2Version Version { get; set; }

        public Argon2Parameters(Argon2Type a_Type, byte[] a_Salt, byte[] a_Secret, byte[] a_Additional,
            Int32 a_Iterations, Int32 a_Memory, Int32 a_Lanes, Argon2Version a_Version)
        {
            Salt= a_Salt.DeepCopy();
            Secret= a_Secret.DeepCopy();
            Additional= a_Additional.DeepCopy();
            Iterations= a_Iterations;
            Memory= a_Memory;
            Lanes= a_Lanes;
            Type= a_Type;
            Version= a_Version;
        } // end cctr

        public void Clear()
        {
            ArrayUtils.ZeroFill(ref salt);
            ArrayUtils.ZeroFill(ref secret);
            ArrayUtils.ZeroFill(ref additional);
        } // end function Clear

    } // end class Argon2Parameters

    public sealed class Argon2iParametersBuilder : Argon2ParametersBuilder
    {
        private Argon2iParametersBuilder()
            : base(Argon2Type.a2tARGON2_i)
        {} // end cctr

        public static IArgon2ParametersBuilder Builder()
        {
            var builder = new Argon2iParametersBuilder();
            return builder as IArgon2ParametersBuilder;
        } // end function Builder

    } // end class Argon2iParametersBuilder

    public sealed class Argon2dParametersBuilder : Argon2ParametersBuilder
    {
        private Argon2dParametersBuilder()
            : base(Argon2Type.a2tARGON2_d)
        {
        } // end cctr

        public static IArgon2ParametersBuilder Builder()
        {
            var builder = new Argon2dParametersBuilder();
            return builder as IArgon2ParametersBuilder;
        } // end function Builder

    } // end class Argon2dParametersBuilder

    public sealed class Argon2idParametersBuilder : Argon2ParametersBuilder
    {
        private Argon2idParametersBuilder()
            : base(Argon2Type.a2tARGON2_id)
        {} // end cctr

        public static IArgon2ParametersBuilder Builder()
        {
            var builder = new Argon2idParametersBuilder();
            return builder as IArgon2ParametersBuilder; ;
        } // end function Builder

    } // end class Argon2idParametersBuilder

}