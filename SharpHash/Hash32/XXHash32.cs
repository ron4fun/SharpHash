///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019  Mbadiwe Nnaemeka Ronald
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

namespace SharpHash.Hash32
{
    internal sealed class XXHash32 : Hash, IHash32, IHashWithKey, ITransformBlock
    {
        private UInt32 key, hash;

        static private readonly UInt32 CKEY = 0x0;

        static private readonly UInt32 PRIME32_1 = 2654435761;
        static private readonly UInt32 PRIME32_2 = 2246822519;
        static private readonly UInt32 PRIME32_3 = 3266489917;
        static private readonly UInt32 PRIME32_4 = 668265263;
        static private readonly UInt32 PRIME32_5 = 374761393;

        private struct XXH_State
        {
            public UInt64 total_len;
            public UInt32 memsize, v1, v2, v3, v4;
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

        public XXHash32()
         : base(4, 16)
        {
            key = CKEY;
            state.memory = new byte[16];
        } // end constructor

        public override void Initialize()
        {
            hash = 0;
            state.v1 = key + PRIME32_1 + PRIME32_2;
            state.v2 = key + PRIME32_2;
            state.v3 = key + 0;
            state.v4 = key - PRIME32_1;
            state.total_len = 0;
            state.memsize = 0;
        } // end function Initialize

        public override IHash Clone()
        {
            XXHash32 HashInstance = new XXHash32();

            HashInstance.key = key;
            HashInstance.hash = hash;
            HashInstance.state = state.Clone();

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            UInt32 _v1, _v2, _v3, _v4;

            unsafe
            {
                byte* ptrTemp, ptrBuffer;

                fixed (byte* ptrData = a_data, ptrMemory = state.memory)
                {
                    ptrBuffer = ptrData + a_index;

                    state.total_len = state.total_len + (UInt64)a_length;

                    if ((state.memsize + (UInt32)a_length) < (UInt32)16)
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

                        Utils.Utils.memmove((IntPtr)ptrTemp, (IntPtr)ptrBuffer, (Int32)(16 - state.memsize));

                        state.v1 = PRIME32_1 * Bits.RotateLeft32(state.v1 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrMemory, 0), 13);
                        state.v2 = PRIME32_1 * Bits.RotateLeft32(state.v2 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrMemory, 4), 13);
                        state.v3 = PRIME32_1 * Bits.RotateLeft32(state.v3 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrMemory, 8), 13);
                        state.v4 = PRIME32_1 * Bits.RotateLeft32(state.v4 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrMemory, 12), 13);

                        ptrBuffer = ptrBuffer + (16 - state.memsize);

                        state.memsize = 0;
                    } // end if

                    if (ptrBuffer <= (ptrEnd - 16))
                    {
                        _v1 = state.v1;
                        _v2 = state.v2;
                        _v3 = state.v3;
                        _v4 = state.v4;

                        byte* ptrLimit = ptrEnd - 16;

                        do
                        {
                            _v1 = PRIME32_1 * Bits.RotateLeft32(_v1 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrBuffer, 0), 13);
                            _v2 = PRIME32_1 * Bits.RotateLeft32(_v2 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrBuffer, 4), 13);
                            _v3 = PRIME32_1 * Bits.RotateLeft32(_v3 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrBuffer, 8), 13);
                            _v4 = PRIME32_1 * Bits.RotateLeft32(_v4 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrBuffer, 12), 13);
                            ptrBuffer += 16;
                        }
                        while (ptrBuffer <= ptrLimit);

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
            }
        } // end function TransformBytes

        public override IHashResult TransformFinal()
        {
            unsafe
            {
                byte* ptrEnd, ptrBuffer;

                fixed (byte* bPtr = state.memory)
                {
                    if (state.total_len >= (UInt64)16)
                        hash = Bits.RotateLeft32(state.v1, 1) + Bits.RotateLeft32(state.v2, 7) +
                        Bits.RotateLeft32(state.v3, 12) + Bits.RotateLeft32(state.v4, 18);
                    else
                        hash = key + PRIME32_5;

                    hash += (UInt32)state.total_len;

                    ptrBuffer = bPtr;

                    ptrEnd = ptrBuffer + state.memsize;
                    while ((ptrBuffer + 4) <= ptrEnd)
                    {
                        hash = hash + Converters.ReadBytesAsUInt32LE((IntPtr)ptrBuffer, 0) * PRIME32_3;
                        hash = Bits.RotateLeft32(hash, 17) * PRIME32_4;
                        ptrBuffer += 4;
                    } // end while

                    while (ptrBuffer < ptrEnd)
                    {
                        hash = hash + (UInt32)(*ptrBuffer) * PRIME32_5;
                        hash = Bits.RotateLeft32(hash, 11) * PRIME32_1;
                        ptrBuffer++;
                    } // end while

                    hash = hash ^ (hash >> 15);
                    hash = hash * PRIME32_2;
                    hash = hash ^ (hash >> 13);
                    hash = hash * PRIME32_3;
                    hash = hash ^ (hash >> 16);
                }
            }

            IHashResult result = new HashResult(hash);

            Initialize();

            return result;
        } // end function TransformFinal

        public Int32? KeyLength
        {
            get
            {
                return 4;
            }
        } // end property KeyLength

        public byte[] Key
        {
            get
            {
                return Converters.ReadUInt32AsBytesLE(key);
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
                            key = Converters.ReadBytesAsUInt32LE((IntPtr)vPtr, 0);
                        }
                    }
                } // end else
            }
        } // end property GetKey
    } // end class XXHash32
}