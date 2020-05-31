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
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal class Blake3 : Hash, ICryptoNotBuiltIn, ITransformBlock
    {
        public static readonly string InvalidXOFSize = "XOFSize in Bits must be Multiples of 8 and be Greater than Zero Bytes";
        public static readonly string InvalidKeyLength = "\"Key\" Length Must Not Be Greater Than {0}, \"{1}\"";
        public static readonly string MaximumOutputLengthExceeded = "Maximum Output Length is 2^64 Bytes";
        public static readonly string OutputBufferTooShort = "Output Buffer Too Short";
        public static readonly string OutputLengthInvalid = "Output Length is above the Digest Length";
        public static readonly string WritetoXofAfterReadError = "\"{0}\" Write to Xof after Read not Allowed";

        private const Int32 ChunkSize = 1024;
        private const Int32 BlockSizeInBytes = 64;
        internal const Int32 KeyLengthInBytes = 32;

        private const UInt32 flagChunkStart = (UInt32)(1 << 0);
        private const UInt32 flagChunkEnd = (UInt32)(1 << 1);
        private const UInt32 flagParent = (UInt32)(1 << 2);
        private const UInt32 flagRoot = (UInt32)(1 << 3);
        protected const UInt32 flagKeyedHash = (UInt32)(1 << 4);
        private const UInt32 flagDeriveKeyContext = (UInt32)(1 << 5);
        private const UInt32 flagDeriveKeyMaterial = (UInt32)(1 << 6);

        // maximum size in bytes this digest output reader can produce
        private const UInt64 MaxDigestLengthInBytes = UInt64.MaxValue;

        internal static readonly UInt32[] IV = new UInt32[] {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };


        protected Blake3ChunkState CS;
        protected Blake3OutputReader OutputReader;
        protected UInt32[] Key = null;
        protected UInt32 Flags;

        // log(n) set of Merkle subtree roots, at most one per height.
        // stack [54][8]uint32
        protected UInt32[][] Stack = null; // 2^54 * chunkSize = 2^64
                                    // bit vector indicating which stack elems are valid; also number of chunks added
        protected UInt64 Used;

        // A Blake3Node represents a chunk or parent in the BLAKE3 Merkle tree. In BLAKE3
        // terminology, the elements of the bottom layer (aka "leaves") of the tree are
        // called chunk nodes, and the elements of upper layers (aka "interior nodes")
        // are called parent nodes.
        //
        // Computing a BLAKE3 hash involves splitting the input into chunk nodes, then
        // repeatedly merging these nodes into parent nodes, until only a single "root"
        // node remains. The root node can then be used to generate up to 2^64 - 1 bytes
        // of pseudorandom output.
        protected struct Blake3Node
        {
            // the chaining value from the previous state
            public UInt32[] CV;
            // the current state
            public UInt32[] Block;
            public UInt64 Counter;
            public UInt32 BlockLen, Flags;

            public Blake3Node Clone()
            {
                Blake3Node result = DefaultBlake3Node();

                result.CV = CV.DeepCopy();
                result.Block = Block.DeepCopy();
                result.Counter = Counter;
                result.BlockLen = BlockLen;
                result.Flags = Flags;

                return result;
            } // end function Clone

            // ChainingValue returns the first 8 words of the compressed node. This is used
            // in two places. First, when a chunk node is being constructed, its cv is
            // overwritten with this value after each block of input is processed. Second,
            // when two nodes are merged into a parent, each of their chaining values
            // supplies half of the new node's block.
            public void ChainingValue(ref UInt32[] a_Result)
            {
                UInt32[] LFull = new UInt32[16];
                Compress(ref LFull);
                Utils.Utils.Memmove(ref a_Result, LFull, 8);
            } // end function 

            // compress is the core hash function, generating 16 pseudorandom words from a
            // node.
            // NOTE: we unroll all of the rounds, as well as the permutations that occur
            // between rounds.
            public void Compress(ref UInt32[] a_PtrState)
            {
                // initializes state here (in this case, a_PtrState)
                a_PtrState[0] = CV[0];
                a_PtrState[1] = CV[1];
                a_PtrState[2] = CV[2];
                a_PtrState[3] = CV[3];
                a_PtrState[4] = CV[4];
                a_PtrState[5] = CV[5];
                a_PtrState[6] = CV[6];
                a_PtrState[7] = CV[7];
                a_PtrState[8] = IV[0];
                a_PtrState[9] = IV[1];
                a_PtrState[10] = IV[2];
                a_PtrState[11] = IV[3];
                a_PtrState[12] = (UInt32)Counter;
                a_PtrState[13] = (UInt32)(Counter >> 32);
                a_PtrState[14] = BlockLen;
                a_PtrState[15] = Flags;

                // NOTE: we unroll all of the rounds, as well as the permutations that occur
                // between rounds.
                // Round 0
                // Mix the columns.
                G(ref a_PtrState, 0, 4, 8, 12, Block[0], Block[1]);
                G(ref a_PtrState, 1, 5, 9, 13, Block[2], Block[3]);
                G(ref a_PtrState, 2, 6, 10, 14, Block[4], Block[5]);
                G(ref a_PtrState, 3, 7, 11, 15, Block[6], Block[7]);

                // Mix the rows.
                G(ref a_PtrState, 0, 5, 10, 15, Block[8], Block[9]);
                G(ref a_PtrState, 1, 6, 11, 12, Block[10], Block[11]);
                G(ref a_PtrState, 2, 7, 8, 13, Block[12], Block[13]);
                G(ref a_PtrState, 3, 4, 9, 14, Block[14], Block[15]);

                // Round 1
                // Mix the columns.
                G(ref a_PtrState, 0, 4, 8, 12, Block[2], Block[6]);
                G(ref a_PtrState, 1, 5, 9, 13, Block[3], Block[10]);
                G(ref a_PtrState, 2, 6, 10, 14, Block[7], Block[0]);
                G(ref a_PtrState, 3, 7, 11, 15, Block[4], Block[13]);

                // Mix the rows.
                G(ref a_PtrState, 0, 5, 10, 15, Block[1], Block[11]);
                G(ref a_PtrState, 1, 6, 11, 12, Block[12], Block[5]);
                G(ref a_PtrState, 2, 7, 8, 13, Block[9], Block[14]);
                G(ref a_PtrState, 3, 4, 9, 14, Block[15], Block[8]);

                // Round 2
                // Mix the columns.
                G(ref a_PtrState, 0, 4, 8, 12, Block[3], Block[4]);
                G(ref a_PtrState, 1, 5, 9, 13, Block[10], Block[12]);
                G(ref a_PtrState, 2, 6, 10, 14, Block[13], Block[2]);
                G(ref a_PtrState, 3, 7, 11, 15, Block[7], Block[14]);

                // Mix the rows.
                G(ref a_PtrState, 0, 5, 10, 15, Block[6], Block[5]);
                G(ref a_PtrState, 1, 6, 11, 12, Block[9], Block[0]);
                G(ref a_PtrState, 2, 7, 8, 13, Block[11], Block[15]);
                G(ref a_PtrState, 3, 4, 9, 14, Block[8], Block[1]);

                // Round 3
                // Mix the columns.
                G(ref a_PtrState, 0, 4, 8, 12, Block[10], Block[7]);
                G(ref a_PtrState, 1, 5, 9, 13, Block[12], Block[9]);
                G(ref a_PtrState, 2, 6, 10, 14, Block[14], Block[3]);
                G(ref a_PtrState, 3, 7, 11, 15, Block[13], Block[15]);

                // Mix the rows.
                G(ref a_PtrState, 0, 5, 10, 15, Block[4], Block[0]);
                G(ref a_PtrState, 1, 6, 11, 12, Block[11], Block[2]);
                G(ref a_PtrState, 2, 7, 8, 13, Block[5], Block[8]);
                G(ref a_PtrState, 3, 4, 9, 14, Block[1], Block[6]);

                // Round 4
                // Mix the columns.
                G(ref a_PtrState, 0, 4, 8, 12, Block[12], Block[13]);
                G(ref a_PtrState, 1, 5, 9, 13, Block[9], Block[11]);
                G(ref a_PtrState, 2, 6, 10, 14, Block[15], Block[10]);
                G(ref a_PtrState, 3, 7, 11, 15, Block[14], Block[8]);

                // Mix the rows.
                G(ref a_PtrState, 0, 5, 10, 15, Block[7], Block[2]);
                G(ref a_PtrState, 1, 6, 11, 12, Block[5], Block[3]);
                G(ref a_PtrState, 2, 7, 8, 13, Block[0], Block[1]);
                G(ref a_PtrState, 3, 4, 9, 14, Block[6], Block[4]);

                // Round 5
                // Mix the columns.
                G(ref a_PtrState, 0, 4, 8, 12, Block[9], Block[14]);
                G(ref a_PtrState, 1, 5, 9, 13, Block[11], Block[5]);
                G(ref a_PtrState, 2, 6, 10, 14, Block[8], Block[12]);
                G(ref a_PtrState, 3, 7, 11, 15, Block[15], Block[1]);

                // Mix the rows.
                G(ref a_PtrState, 0, 5, 10, 15, Block[13], Block[3]);
                G(ref a_PtrState, 1, 6, 11, 12, Block[0], Block[10]);
                G(ref a_PtrState, 2, 7, 8, 13, Block[2], Block[6]);
                G(ref a_PtrState, 3, 4, 9, 14, Block[4], Block[7]);

                // Round 6
                // Mix the columns.
                G(ref a_PtrState, 0, 4, 8, 12, Block[11], Block[15]);
                G(ref a_PtrState, 1, 5, 9, 13, Block[5], Block[0]);
                G(ref a_PtrState, 2, 6, 10, 14, Block[1], Block[9]);
                G(ref a_PtrState, 3, 7, 11, 15, Block[8], Block[6]);

                // Mix the rows.
                G(ref a_PtrState, 0, 5, 10, 15, Block[14], Block[10]);
                G(ref a_PtrState, 1, 6, 11, 12, Block[2], Block[12]);
                G(ref a_PtrState, 2, 7, 8, 13, Block[3], Block[4]);
                G(ref a_PtrState, 3, 4, 9, 14, Block[7], Block[13]);

                // compression finalization

                a_PtrState[0] = a_PtrState[0] ^ a_PtrState[8];
                a_PtrState[1] = a_PtrState[1] ^ a_PtrState[9];
                a_PtrState[2] = a_PtrState[2] ^ a_PtrState[10];
                a_PtrState[3] = a_PtrState[3] ^ a_PtrState[11];
                a_PtrState[4] = a_PtrState[4] ^ a_PtrState[12];
                a_PtrState[5] = a_PtrState[5] ^ a_PtrState[13];
                a_PtrState[6] = a_PtrState[6] ^ a_PtrState[14];
                a_PtrState[7] = a_PtrState[7] ^ a_PtrState[15];
                a_PtrState[8] = a_PtrState[8] ^ CV[0];
                a_PtrState[9] = a_PtrState[9] ^ CV[1];
                a_PtrState[10] = a_PtrState[10] ^ CV[2];
                a_PtrState[11] = a_PtrState[11] ^ CV[3];
                a_PtrState[12] = a_PtrState[12] ^ CV[4];
                a_PtrState[13] = a_PtrState[13] ^ CV[5];
                a_PtrState[14] = a_PtrState[14] ^ CV[6];
                a_PtrState[15] = a_PtrState[15] ^ CV[7];
            } // end function Compress

            private void G(ref UInt32[] a_PtrState, UInt32 A, UInt32 B, UInt32 C, UInt32 D, UInt32 X, UInt32 Y)
            {
                UInt32 LA, LB, LC, LD;

                LA = a_PtrState[A];
                LB = a_PtrState[B];
                LC = a_PtrState[C];
                LD = a_PtrState[D];

                LA = LA + LB + X;
                LD = Bits.RotateRight32(LD ^ LA, 16);
                LC = LC + LD;
                LB = Bits.RotateRight32(LB ^ LC, 12);
                LA = LA + LB + Y;
                LD = Bits.RotateRight32(LD ^ LA, 8);
                LC = LC + LD;
                LB = Bits.RotateRight32(LB ^ LC, 7);

                a_PtrState[A] = LA;
                a_PtrState[B] = LB;
                a_PtrState[C] = LC;
                a_PtrState[D] = LD;
            } // end function G

            public static Blake3Node DefaultBlake3Node()
            {
                Blake3Node result = new Blake3Node();

                result.CV = new uint[8];
                result.Block = new uint[16];
                result.Counter = 0;
                result.BlockLen = 0;
                result.Flags = 0;

                return result;
            } // end function DefaultBlake3Node

            public static Blake3Node CreateBlake3Node(UInt32[] a_CV, UInt32[] a_Block, 
                UInt64 a_Counter, UInt32 a_BlockLen, UInt32 a_Flags)
            {
                Blake3Node result = DefaultBlake3Node();

                result.CV = a_CV.DeepCopy();
                result.Block = a_Block.DeepCopy();
                result.Counter = a_Counter;
                result.BlockLen = a_BlockLen;
                result.Flags = a_Flags;

                return result;
            } // end function CreateBlake3Node

            public static Blake3Node ParentNode(UInt32[] a_Left, UInt32[] a_Right, UInt32[] a_Key, UInt32 a_Flags)
            {
                UInt32[] LBlockWords = Utils.Utils.Concat(a_Left, a_Right);
                return CreateBlake3Node(a_Key, LBlockWords, 0, BlockSizeInBytes, a_Flags | flagParent);
            } // end funtion ParentNode

        }; // end struct Blake3Node

        // Blake3ChunkState manages the state involved in hashing a single chunk of input.
        protected struct Blake3ChunkState
        {
            private Blake3Node N;
            private byte[] Block;
            public Int32 BlockLen, BytesConsumed;

            public Blake3ChunkState Clone()
            {
                Blake3ChunkState result = DefaultBlake3ChunkState();

                result.N = N.Clone();
                result.Block = Block.DeepCopy();
                result.BlockLen = BlockLen;
                result.BytesConsumed = BytesConsumed;

                return result;
            } // end function Clone

            // ChunkCounter is the index of this chunk, i.e. the number of chunks that have
            // been processed prior to this one.
            public UInt64 ChunkCounter()
            {
                return N.Counter;
            } // end function ChunkCounter

            public bool Complete()
            {
                return BytesConsumed == ChunkSize;
            } // end function Complete

            // node returns a node containing the chunkState's current state, with the
            // ChunkEnd flag set.
            public unsafe Blake3Node Node()
            {
                Blake3Node result = N.Clone();

                fixed(byte* blockPtr = Block)
                {
                    fixed (UInt32* resultPtr = result.Block)
                    {
                        // pad the remaining space in the block with zeros
                        Utils.Utils.Memset((IntPtr)blockPtr + BlockLen, (byte)0, (Block.Length - BlockLen) * sizeof(byte));
                        Converters.le32_copy((IntPtr)blockPtr, 0, (IntPtr)resultPtr, 0, BlockSizeInBytes);
                    }
                }               

                result.BlockLen = (UInt32)BlockLen;
                result.Flags = result.Flags | flagChunkEnd;

                return result;
            } // end function Node

            // update incorporates input into the chunkState.
            public unsafe void Update(byte* dataPtr, Int32 a_DataLength)
            {
                Int32 LCount, LIndex;

                LIndex = 0;

                fixed (byte* LBytePtr = Block)
                {
                    fixed (UInt32* LCardinalPtr = N.Block)
                    {
                        fixed (UInt32* LCVPtr = N.CV)
                        {
                            while (a_DataLength > 0)
                            {
                                // If the block buffer is full, compress it and clear it. More
                                // input is coming, so this compression is not flagChunkEnd.
                                if (BlockLen == BlockSizeInBytes)
                                {
                                    // copy the chunk block (bytes) into the node block and chain it.
                                    Converters.le32_copy((IntPtr)LBytePtr, 0, (IntPtr)LCardinalPtr, 0, BlockSizeInBytes);
                                    N.ChainingValue(ref N.CV);
                                    // clear the start flag for all but the first block
                                    N.Flags = N.Flags & (N.Flags ^ flagChunkStart);
                                    BlockLen = 0;
                                } // end if

                                // Copy input bytes into the chunk block.
                                LCount = Math.Min(BlockSizeInBytes - BlockLen, a_DataLength);
                                Utils.Utils.Memmove((IntPtr)(LBytePtr + BlockLen), (IntPtr)(dataPtr + LIndex), LCount);

                                BlockLen += LCount;
                                BytesConsumed += LCount;
                                LIndex += LCount;
                                a_DataLength -= LCount;
                            } // end while
                        }
                    }

                }
            } // end function Update

            public static Blake3ChunkState DefaultBlake3ChunkState()
        {
                Blake3ChunkState result = new Blake3ChunkState();

                result.N = Blake3Node.DefaultBlake3Node();
                result.Block = new byte[BlockSizeInBytes];
                result.BlockLen = 0;
                result.BytesConsumed = 0;

                return result;
            } // end function DefaultBlake3ChunkState

            public static Blake3ChunkState CreateBlake3ChunkState(UInt32[] a_IV, UInt64 a_ChunkCounter, UInt32 a_Flags)
            {
                Blake3ChunkState result = DefaultBlake3ChunkState();

                result.N.CV = a_IV.DeepCopy();
                result.N.Counter = a_ChunkCounter;
                result.N.BlockLen = BlockSizeInBytes;
                // compress the first block with the start flag set
                result.N.Flags = a_Flags | flagChunkStart;

                return result;
            } // end function CreateBlake3ChunkState

        }; // end struct Blake3ChunkState

        protected struct Blake3OutputReader
        {
            public Blake3Node N;
            public byte[] Block;
            public UInt64 Offset;

            public Blake3OutputReader Clone()
            {
                Blake3OutputReader result = DefaultBlake3OutputReader();

                result.N = N.Clone();
                result.Block = Block.DeepCopy();
                result.Offset = Offset;

                return result;
            } // end function  Clone

            public unsafe void Read(ref byte[] a_Destination, UInt64 a_DestinationOffset, UInt64 a_OutputLength)
            {
                UInt64 LRemainder, LBlockOffset, LDiff;
                Int32 LCount;

                UInt32[] LWords = new UInt32[16];

                if (Offset == MaxDigestLengthInBytes)
                    throw new ArgumentOutOfRangeHashLibException(MaximumOutputLengthExceeded);
                else
                {
                    LRemainder = MaxDigestLengthInBytes - Offset;
                    if (a_OutputLength > LRemainder)
                        a_OutputLength = LRemainder;
                } // end else

                fixed(UInt32* LPtrCardinal = LWords)
                {
                    fixed (byte* LPtrByte = Block)
                    {
                        while (a_OutputLength > 0)
                        {
                            if ((Offset & (BlockSizeInBytes - 1)) == 0)
                            {
                                N.Counter = Offset / (UInt64)BlockSizeInBytes;
                                N.Compress(ref LWords);
                                Converters.le32_copy((IntPtr)LPtrCardinal, 0, (IntPtr)LPtrByte, 0, BlockSizeInBytes);
                            }

                            LBlockOffset = Offset & (BlockSizeInBytes - 1);

                            LDiff = (UInt64)Block.Length - LBlockOffset;

                            LCount = (Int32)Math.Min(a_OutputLength, LDiff);

                            Utils.Utils.Memmove(ref a_Destination, Block, LCount, (Int32)LBlockOffset, (Int32)a_DestinationOffset);

                            a_OutputLength -= (UInt64)LCount;
                            a_DestinationOffset += (UInt64)LCount;
                            Offset += (UInt64)LCount;
                        }
                    }
                }
       
            } // end function Read

            public static Blake3OutputReader DefaultBlake3OutputReader()
            { 
                Blake3OutputReader result = new Blake3OutputReader();

                result.Block = new byte[BlockSizeInBytes];
                result.N = Blake3Node.DefaultBlake3Node();
                result.Offset = 0;

                return result;
            } // end function Blake3OutputReader

        }; // end struct Blake3OutputReader

        private Blake3Node RootNode()
        {
            Int32 LIdx, LTrailingZeros64, LLen64;

            Blake3Node result = CS.Node();
            UInt32[] LTemp = new UInt32[8];

            LTrailingZeros64 = TrailingZeros64(Used);
            LLen64 = Len64(Used);

            for (LIdx = LTrailingZeros64; LIdx < LLen64; LIdx++)
            {
                if (HasSubTreeAtHeight(LIdx))
                {
                    result.ChainingValue(ref LTemp);
                    result = Blake3Node.ParentNode(Stack[LIdx], LTemp, Key, Flags);
                }
            }

            result.Flags = result.Flags | flagRoot;

            return result;
        } // end function RootNode

        private bool HasSubTreeAtHeight(Int32 a_Idx)
        {
            return (Used & ((UInt32)1 << a_Idx)) != 0;
        } // end function HasSubTreeAtHeight

        // AddChunkChainingValue appends a chunk to the right edge of the Merkle tree.
        private void AddChunkChainingValue(UInt32[] a_CV)
        {
            // seek to first open stack slot, merging subtrees as we go
            Int32 LIdx = 0;
            while (HasSubTreeAtHeight(LIdx))
            {
                Blake3Node.ParentNode(Stack[LIdx], a_CV, Key, Flags).ChainingValue(ref a_CV);
                LIdx++;
            }
          
            Stack[LIdx] = a_CV.DeepCopy();
            Used++;
        } // end function AddChunkChainingValue

        // Len64 returns the minimum number of bits required to represent x; the result is 0 for x == 0.
        private static Int32 Len64(UInt64 a_Value)
        {
            Int32 result = 0;
            if (a_Value >= (1 << 32))
            {
                a_Value = a_Value >> 32;
                result = 32;
            }
            if (a_Value >= (1 << 16))
            {
                a_Value = a_Value >> 16;
                result = result + 16;
            }
            if (a_Value >= (1 << 8))
            {
                a_Value = a_Value >> 8;
                result = result + 8;
            }

            return result + (Int32)(Len8((byte)a_Value));
        } // end function Len64

        private static byte Len8(byte a_Value)
        {
            byte result = 0;
            while (a_Value != 0)
            {
                a_Value = (byte)(a_Value >> 1);
                result++;
            }

            return result;
        } // end function Len8

        private static Int32 TrailingZeros64(UInt64 a_Value)
        {
            if (a_Value == 0) return 64;

            Int32 result = 0;
            while ((a_Value & 1) == 0)
            {
                a_Value = a_Value >> 1;
                result++;
            }

            return result;
        } // end function TrailingZeros64

        public override string Name
        {
            get => String.Format("{0}_{1}", this.GetType().Name, HashSize * 8);
        } // end property Name

        protected void InternalDoOutput(ref byte[] a_Destination, UInt64 a_DestinationOffset, UInt64 a_OutputLength)
        {
            OutputReader.Read(ref a_Destination, a_DestinationOffset, a_OutputLength);
        } // end function InternalDoOutput

        protected unsafe void Finish()
        {
            OutputReader.N = RootNode();
        } // end function Finish

        public static unsafe Blake3 CreateBlake3(Int32 a_HashSize, byte[] a_Key)
        {
            Int32 LKeyLength;
            Blake3 blake3 = null;
            UInt32[] LKeyWords = new UInt32[8];           

            if (a_Key.Empty())
            {
                LKeyWords = IV.DeepCopy();
                blake3 = new Blake3(a_HashSize, LKeyWords, 0);
            }
            else
            {
                LKeyLength = a_Key.Length;
                if (LKeyLength != KeyLengthInBytes)
                    throw new ArgumentOutOfRangeHashLibException(
                        String.Format(InvalidKeyLength, KeyLengthInBytes, LKeyLength));
                
                fixed(byte* keyPtr = a_Key)
                {
                    fixed (UInt32* keywordPtr = LKeyWords)
                    {
                        Converters.le32_copy((IntPtr)keyPtr, 0, (IntPtr)keywordPtr, 0, LKeyLength);
                    }
                }              

                blake3 = new Blake3(a_HashSize, LKeyWords, flagKeyedHash);
            }

            return blake3;
        } // end cctr

        public Blake3(Int32 a_HashSize, UInt32[] a_KeyWords, UInt32 a_Flags)
            : base(a_HashSize, BlockSizeInBytes)
        {
            Int32 LIdx;

            Key = a_KeyWords.DeepCopy();
            Flags = a_Flags;

            Stack = new UInt32[54][];
            for (LIdx = 0; LIdx < Stack.Length; LIdx++)
                Stack[LIdx] = new UInt32[8];

        } // end cctr

        public static Blake3 CreateBlake3(HashSizeEnum a_HashSize = HashSizeEnum.HashSize256, byte[] a_Key = null)
        {
            return CreateBlake3((Int32)a_HashSize, a_Key);
        } // end cctr

        public override unsafe void Initialize()
        {
            CS = Blake3ChunkState.CreateBlake3ChunkState(Key, 0, Flags);
            OutputReader = Blake3OutputReader.DefaultBlake3OutputReader();

            for (Int32 i = 0; i < Stack.Length; i++)
                ArrayUtils.ZeroFill(ref Stack[i]);

            Used = 0;
        } // end function Initialize

        public override unsafe void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            byte* LPtrAData;
            Int32 LCount;
            UInt32[] LCV = new UInt32[8];

            fixed (UInt32* LPtrCV = LCV)
            {
                fixed (byte* dataPtr = a_data)
                {
                    LPtrAData = dataPtr + a_index;

                    while (a_length > 0)
                    {
                        // If the current chunk is complete, finalize it and add it to the tree,
                        // then reset the chunk state (but keep incrementing the counter across
                        // chunks).
                        if (CS.Complete())
                        {
                            CS.Node().ChainingValue(ref LCV);
                            AddChunkChainingValue(LCV);
                            CS = Blake3ChunkState.CreateBlake3ChunkState(Key, CS.ChunkCounter() + 1, Flags);
                        }

                        // Compress input bytes into the current chunk state.
                        LCount = Math.Min(ChunkSize - CS.BytesConsumed, a_length);
                        CS.Update(LPtrAData, LCount);

                        LPtrAData += LCount;
                        a_length -= LCount;
                    }
                }
            }
            
        } // end function TransformBytes

        public override unsafe IHashResult TransformFinal()
        {
            Finish();

            byte[] Buffer = new byte[HashSize];

            InternalDoOutput(ref Buffer, 0, (UInt64)Buffer.Length);

            IHashResult result = new HashResult(Buffer);

            Initialize();

            return result;
        } // end function TransformFinal

        public override IHash Clone()
        {
            Blake3 blake = new Blake3(HashSize, Key, Flags);

            blake.CS = CS.Clone();
            blake.OutputReader = OutputReader.Clone();

            for(Int32 i = 0; i < Stack.Length; i++)
                blake.Stack[i] = Stack[i].DeepCopy();
            
            blake.Used = Used;

            blake.BufferSize = BufferSize;

            return blake;
        } // end function Clone

        // DeriveKey derives a subkey from ctx and srcKey. ctx should be hardcoded,
        // globally unique, and application-specific. A good format for ctx strings is:
        //
        // [application] [commit timestamp] [purpose]
        //
        // e.g.:
        //
        // example.com 2019-12-25 16:18:03 session tokens v1
        //
        // The purpose of these requirements is to ensure that an attacker cannot trick
        // two different applications into using the same context string.
        public static unsafe void DeriveKey(byte[] a_SrcKey, byte[] a_Ctx, byte[] a_SubKey)
        {
            const Int32 derivationIVLen = 32;
            IXOF LXof;

            UInt32[] LIVWords = IV.DeepCopy();

            // construct the derivation Hasher and get the DerivationIV
            byte[] LDerivationIV = (new Blake3(derivationIVLen, LIVWords, flagDeriveKeyContext) as IHash).ComputeBytes(a_Ctx).GetBytes();

            fixed(byte* derivePtr = LDerivationIV)
            {
                fixed (UInt32* wordPtr = LIVWords)
                {
                    Converters.le32_copy((IntPtr)derivePtr, 0, (IntPtr)wordPtr, 0, KeyLengthInBytes);
                }
            }

            // derive the SubKey
            LXof = new Blake3XOF(32, LIVWords, flagDeriveKeyMaterial) as IXOF;
            LXof.XOFSizeInBits = (UInt64)a_SubKey.Length * 8;
            LXof.Initialize();
            LXof.TransformBytes(a_SrcKey);
            LXof.DoOutput(ref a_SubKey, 0, (UInt64)a_SubKey.Length);
            LXof.Initialize();

        } // end function DeriveKey

    } // end class Blake3

    internal sealed class Blake3XOF : Blake3, IXOF
    {
        private bool Finalized;

        private UInt64 _XofSizeInBits;
        public UInt64 XOFSizeInBits
        {
            get => _XofSizeInBits;
            set => SetXOFSizeInBitsInternal(value);
        }

        public static unsafe Blake3XOF CreateBlake3XOF(Int32 a_HashSize, byte[] a_Key)
        {
            Blake3XOF blake = null;
            UInt32[] LKeyWords = new UInt32[8];

            if (a_Key.Empty())
            {
                LKeyWords = IV.DeepCopy();
                blake = new Blake3XOF(a_HashSize, LKeyWords, 0);
            }
            else
            {
                Int32 LKeyLength = a_Key.Length;
                if (LKeyLength != KeyLengthInBytes)
                    throw new ArgumentOutOfRangeHashLibException(
                        String.Format(InvalidKeyLength, KeyLengthInBytes, LKeyLength));

                fixed (byte* keyPtr = a_Key)
                {
                    fixed (UInt32* keywordPtr = LKeyWords)
                    {
                        Converters.le32_copy((IntPtr)keyPtr, 0, (IntPtr)keywordPtr, 0, LKeyLength);
                    }
                }

                blake = new Blake3XOF(a_HashSize, LKeyWords, flagKeyedHash);
            }

            blake.Finalized = false;

            return blake;
        } // end cctr
        
        public Blake3XOF(Int32 a_HashSize, UInt32[] a_KeyWords, UInt32 a_Flags)
            : base(a_HashSize, a_KeyWords, a_Flags)
        {
            Finalized = false;
        } // end cctr

        public override string Name
        {
            get => this.GetType().Name;
        } // end property Name

        public override void Initialize()
        {
            Finalized = false;
            base.Initialize();
        } // end function Initialize

        public override IHash Clone()
        {
            // Xof Cloning
            IXOF LXof = (CreateBlake3XOF(HashSize, null) as IXOF);
            LXof.XOFSizeInBits = (this as IXOF).XOFSizeInBits;

            // Blake3XOF Cloning
            Blake3XOF HashInstance = (LXof as Blake3XOF);
            HashInstance.Finalized = Finalized;

            // Internal Blake3 Cloning
            HashInstance.CS = CS.Clone();
            HashInstance.OutputReader = OutputReader.Clone();

            for (Int32 i = 0; i < Stack.Length; i++)
                HashInstance.Stack[i] = Stack[i].DeepCopy();

            HashInstance.Used = Used;
            HashInstance.Flags = Flags;
            HashInstance.Key = Key.DeepCopy();

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

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

            Initialize();

            IHashResult result = new HashResult(buffer);

            return result;
        } // end function TransformFinal

        public unsafe void DoOutput(ref byte[] a_destination, UInt64 a_destinationOffset, UInt64 a_outputLength)
        {
            if ((UInt64)a_destination.Length - a_destinationOffset < a_outputLength)
                throw new ArgumentOutOfRangeHashLibException(OutputBufferTooShort);

            if ((OutputReader.Offset + a_outputLength) > (XOFSizeInBits >> 3))
                throw new ArgumentOutOfRangeHashLibException(OutputLengthInvalid);

            if (!Finalized)
            {
                Finish();
                Finalized = true;
            }

            InternalDoOutput(ref a_destination, a_destinationOffset, a_outputLength);
        } // end function DoOutput

        private IXOF SetXOFSizeInBitsInternal(UInt64 a_XofSizeInBits)
        {
            UInt64 xofSizeInBytes = a_XofSizeInBits >> 3;
            if (((a_XofSizeInBits & 0x7) != 0) || (xofSizeInBytes < 1))
                throw new ArgumentInvalidHashLibException(InvalidXOFSize);

            _XofSizeInBits = a_XofSizeInBits;

            return this;
        }

        private byte[] GetResult()
        {
            UInt64 xofSizeInBytes = XOFSizeInBits >> 3;

            byte[] result = new byte[xofSizeInBytes];

            DoOutput(ref result, 0, xofSizeInBytes);

            return result;
        }

    } // end class Blake3XOF

}
