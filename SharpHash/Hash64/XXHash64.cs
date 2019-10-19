using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Hash64
{
    internal sealed class XXHash64 : Hash, IHash64, IHashWithKey, ITransformBlock
    {
        private UInt64 key, hash;

        static private readonly UInt32 CKEY = 0x0;

        static private readonly UInt64 PRIME64_1 = 11400714785074694791;
        static private readonly UInt64 PRIME64_2 = 14029467366897019727;
        static private readonly UInt64 PRIME64_3 = 1609587929392839161;
        static private readonly UInt64 PRIME64_4 = 9650029242287828579;
        static private readonly UInt64 PRIME64_5 = 2870177450012600261;

        struct XXH_State
        {
            public UInt64 total_len, v1, v2, v3, v4;
            public UInt32 memsize;
            public byte[] memory;

            public XXH_State Clone()
            {
                XXH_State result = new XXH_State();
                result.total_len = total_len;
                result.memsize = memsize;
                result.v1 = v1;
                result.v2 = v2;
                result.v3 = v3;
                result.v4 = v4;

                if (!(memory == null || memory.Length == 0))
                {
                    result.memory = new byte[memory.Length];
                    Utils.Utils.memcopy(ref result.memory, memory, memory.Length);
                } // end if
                    
                return result;
            } // end function Clone

        } // end struct XXH_State

        private XXH_State state;

        static private string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        public XXHash64()
         : base(8, 32)
        {
            key = CKEY;
            Array.Resize(ref state.memory, 32);
        } // end constructor

        public override void Initialize()
        {
            hash = 0;
            state.v1 = key + PRIME64_1 + PRIME64_2;
            state.v2 = key + PRIME64_2;
            state.v3 = key + 0;
            state.v4 = key - PRIME64_1;
            state.total_len = 0;
            state.memsize = 0;

        } // end function Initialize

        public override IHash Clone()
        {
            XXHash64 HashInstance = new XXHash64();

            HashInstance.key = key;
            HashInstance.hash = hash;
            HashInstance.state = state.Clone();

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override unsafe void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
	    {
            UInt64 _v1, _v2, _v3, _v4;
            byte* ptrTemp;

            state.total_len = state.total_len + (UInt64)a_length;

            fixed(byte* ptrAData = a_data, ptrMemory = state.memory)
            {
                byte* ptrBuffer = ptrAData + a_index;

                if ((state.memsize + (UInt32)a_length) < (UInt32)32)
                {
                    ptrTemp = ptrMemory + state.memsize;

                    Utils.Utils.memmove((IntPtr)ptrTemp, (IntPtr)ptrBuffer, a_length);

                    state.memsize = state.memsize + (UInt32)a_length;

                    return;
                } // end if

                byte* ptrEnd = ptrBuffer + (UInt32)a_length;

                if (state.memsize > 0)
                {
                    ptrTemp = ptrMemory + state.memsize;

                    Utils.Utils.memmove((IntPtr)ptrTemp, (IntPtr)ptrBuffer, (Int32)(32 - state.memsize));

                    state.v1 = PRIME64_1 * Bits.RotateLeft64(state.v1 + PRIME64_2 * Converters.ReadBytesAsUInt64LE((IntPtr)ptrMemory, 0), 31);
                    state.v2 = PRIME64_1 * Bits.RotateLeft64(state.v2 + PRIME64_2 * Converters.ReadBytesAsUInt64LE((IntPtr)ptrMemory, 8), 31);
                    state.v3 = PRIME64_1 * Bits.RotateLeft64(state.v3 + PRIME64_2 * Converters.ReadBytesAsUInt64LE((IntPtr)ptrMemory, 16), 31);
                    state.v4 = PRIME64_1 * Bits.RotateLeft64(state.v4 + PRIME64_2 * Converters.ReadBytesAsUInt64LE((IntPtr)ptrMemory, 24), 31);

                    ptrBuffer = ptrBuffer + (32 - state.memsize);
                    state.memsize = 0;
                } // end if

                if (ptrBuffer <= (ptrEnd - 32))
                {
                    _v1 = state.v1;
                    _v2 = state.v2;
                    _v3 = state.v3;
                    _v4 = state.v4;

                    byte* ptrLimit = ptrEnd - 32;

                    do
                    {
                        _v1 = PRIME64_1 * Bits.RotateLeft64(_v1 + PRIME64_2 * Converters.ReadBytesAsUInt64LE((IntPtr)ptrBuffer, 0), 31);
                        _v2 = PRIME64_1 * Bits.RotateLeft64(_v2 + PRIME64_2 * Converters.ReadBytesAsUInt64LE((IntPtr)ptrBuffer, 8), 31);
                        _v3 = PRIME64_1 * Bits.RotateLeft64(_v3 + PRIME64_2 * Converters.ReadBytesAsUInt64LE((IntPtr)ptrBuffer, 16), 31);
                        _v4 = PRIME64_1 * Bits.RotateLeft64(_v4 + PRIME64_2 * Converters.ReadBytesAsUInt64LE((IntPtr)ptrBuffer, 24), 31);
                        ptrBuffer += 32;
                    } while (ptrBuffer <= ptrLimit);

                    state.v1 = _v1;
                    state.v2 = _v2;
                    state.v3 = _v3;
                    state.v4 = _v4;
                } // end if

                if (ptrBuffer < ptrEnd)
                {
                    Utils.Utils.memmove((IntPtr)ptrMemory, (IntPtr)ptrBuffer, (Int32)(ptrEnd - ptrBuffer));
                    state.memsize = (UInt32)(ptrEnd - ptrBuffer);
                } // end if
            }
        } // end function TransformBytes

        public override unsafe IHashResult TransformFinal()
        {
            UInt64 _v1, _v2, _v3, _v4;
            byte* ptrEnd, ptrBuffer;

            fixed (byte* bPtr = state.memory)
            {
                if (state.total_len >= (UInt64)32)
                {
                    _v1 = state.v1;
                    _v2 = state.v2;
                    _v3 = state.v3;
                    _v4 = state.v4;

                    hash = Bits.RotateLeft64(_v1, 1) + Bits.RotateLeft64(_v2, 7) + Bits.RotateLeft64(_v3, 12) + Bits.RotateLeft64(_v4, 18);

                    _v1 = Bits.RotateLeft64(_v1 * PRIME64_2, 31) * PRIME64_1;
                    hash = (hash ^ _v1) * PRIME64_1 + PRIME64_4;

                    _v2 = Bits.RotateLeft64(_v2 * PRIME64_2, 31) * PRIME64_1;
                    hash = (hash ^ _v2) * PRIME64_1 + PRIME64_4;

                    _v3 = Bits.RotateLeft64(_v3 * PRIME64_2, 31) * PRIME64_1;
                    hash = (hash ^ _v3) * PRIME64_1 + PRIME64_4;

                    _v4 = Bits.RotateLeft64(_v4 * PRIME64_2, 31) * PRIME64_1;
                    hash = (hash ^ _v4) * PRIME64_1 + PRIME64_4;
                } // end if				 
                else
                    hash = key + PRIME64_5;

                hash += state.total_len;

                ptrBuffer = bPtr;

                ptrEnd = ptrBuffer + state.memsize;
                while ((ptrBuffer + 8) <= ptrEnd)
                {
                    hash = hash ^ (PRIME64_1 * Bits.RotateLeft64(PRIME64_2 * Converters.ReadBytesAsUInt64LE((IntPtr)ptrBuffer, 0), 31));
                    hash = Bits.RotateLeft64(hash, 27) * PRIME64_1 + PRIME64_4;
                    ptrBuffer += 8;
                } // end while

                if ((ptrBuffer + 4) <= ptrEnd)
                {
                    hash = hash ^ Converters.ReadBytesAsUInt32LE((IntPtr)ptrBuffer, 0) * PRIME64_1;
                    hash = Bits.RotateLeft64(hash, 23) * PRIME64_2 + PRIME64_3;
                    ptrBuffer += 4;
                } // end if

                while (ptrBuffer < ptrEnd)
                {
                    hash = hash ^ (*ptrBuffer) * PRIME64_5;
                    hash = Bits.RotateLeft64(hash, 11) * PRIME64_1;
                    ptrBuffer++;
                } // end while

                hash = hash ^ (hash >> 33);
                hash = hash * PRIME64_2;
                hash = hash ^ (hash >> 29);
                hash = hash * PRIME64_3;
                hash = hash ^ (hash >> 32);
            }      

            IHashResult result = new HashResult(hash);

            Initialize();

            return result;
        } // end function TransformFinal

        public Int32? KeyLength
	    {
            get
            {
                return 8;
            }
        } // end property KeyLength

        public byte[] Key
	    {
            get
            {
                return Converters.ReadUInt64AsBytesLE(key);
            }
            set
            {
                if (value == null || value.Length == 0)
                    key = CKEY;
                else
                {
                    if (value.Length != KeyLength)
                        throw new ArgumentHashLibException(String.Format(InvalidKeyLength, KeyLength));

                    unsafe
                    {
                        fixed (byte* vPtr = &value[0])
                        {
                            key = Converters.ReadBytesAsUInt64LE((IntPtr)vPtr, 0);
                        }
                    }

                } // end else
            }
        } // end property GetKey

    } // end class XXHash64

}
