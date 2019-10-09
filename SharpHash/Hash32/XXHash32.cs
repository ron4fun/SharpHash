using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Hash32
{
    public class XXHash32 : Hash, IBlockHash, IHash32, IHashWithKey, ITransformBlock
    {
        private UInt32 key, hash;

        static private UInt32 CKEY = 0x0;

        static private UInt32 PRIME32_1 = 2654435761;
        static private UInt32 PRIME32_2 = 2246822519;
        static private UInt32 PRIME32_3 = 3266489917;
        static private UInt32 PRIME32_4 = 668265263;
        static private UInt32 PRIME32_5 = 374761393;

        private UInt64 total_len;
        private UInt32 memsize, v1, v2, v3, v4;
        private byte[] memory = null;

        static private string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        public XXHash32()
         : base(4, 16)
        {
            key = CKEY;
            memory = new byte[16];
        } // end constructor

        public override void Initialize()
        {
            hash = 0;
            v1 = key + PRIME32_1 + PRIME32_2;
            v2 = key + PRIME32_2;
            v3 = key + 0;
            v4 = key - PRIME32_1;
            total_len = 0;
            memsize = 0;
        } // end function Initialize

        public override IHash Clone()
        {
            XXHash32 HashInstance = new XXHash32();

            HashInstance.key = key;
            HashInstance.hash = hash;
            HashInstance.total_len = total_len;
            HashInstance.memsize = memsize;
            HashInstance.v1 = v1;
            HashInstance.v2 = v2;
            HashInstance.v3 = v3;
            HashInstance.v4 = v4;

            HashInstance.memory = new byte[memory.Length];
            for (Int32 i = 0; i < memory.Length; i++)
                HashInstance.memory[i] = memory[i];

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
	    {
		    UInt32 _v1, _v2, _v3, _v4;

            unsafe
            {
                byte* ptrTemp, ptrBuffer;

                fixed (byte* ptrData = a_data, ptrMemory = memory)
                {
                    ptrBuffer = ptrData + a_index;

                    total_len = total_len + (UInt64)a_length;

                    if ((memsize + (UInt32)a_length) < (UInt32)16)
                    {
                        ptrTemp = ptrMemory + memsize;

                        Utils.Utils.memmove((IntPtr)ptrTemp, (IntPtr)ptrBuffer, a_length);

                        memsize = memsize + (UInt32)a_length;

                        return;
                    } // end if

                    byte* ptrEnd = ptrBuffer + (UInt32)a_length;

                    if (memsize > 0)
                    {
                        ptrTemp = ptrMemory + memsize;

                        Utils.Utils.memmove((IntPtr)ptrTemp, (IntPtr)ptrBuffer, (Int32)(16 - memsize));

                        v1 = PRIME32_1 * Bits.RotateLeft32(v1 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrMemory, 0), 13);
                        v2 = PRIME32_1 * Bits.RotateLeft32(v2 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrMemory, 4), 13);
                        v3 = PRIME32_1 * Bits.RotateLeft32(v3 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrMemory, 8), 13);
                        v4 = PRIME32_1 * Bits.RotateLeft32(v4 + PRIME32_2 * Converters.ReadBytesAsUInt32LE((IntPtr)ptrMemory, 12), 13);

                        ptrBuffer = ptrBuffer + (16 - memsize);

                        memsize = 0;
                    } // end if

                    if (ptrBuffer <= (ptrEnd - 16))
                    {
                        _v1 = v1;
                        _v2 = v2;
                        _v3 = v3;
                        _v4 = v4;

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

                        v1 = _v1;
                        v2 = _v2;
                        v3 = _v3;
                        v4 = _v4;
                    } // end if

                    if (ptrBuffer < ptrEnd)
                    {
                        //ptrTemp = &memory[0];
                        fixed(byte* ptrTemp2 = &memory[0])
                        {
                            Utils.Utils.memmove((IntPtr)ptrTemp2, (IntPtr)ptrBuffer, (Int32)(ptrEnd - ptrBuffer));
                            memsize = (UInt32)(ptrEnd - ptrBuffer);
                        }
                    } // end if

                }
            }
	    } // end function TransformBytes

        public override IHashResult TransformFinal()
        {
            unsafe
            {
                byte* ptrEnd, ptrBuffer;

                fixed (byte* bPtr = &memory[0])
                {
                    if (total_len >= (UInt64)16)
                        hash = Bits.RotateLeft32(v1, 1) + Bits.RotateLeft32(v2, 7) +
                        Bits.RotateLeft32(v3, 12) + Bits.RotateLeft32(v4, 18);
                    else
                        hash = key + PRIME32_5;

                    hash += (UInt32)total_len;

                    ptrBuffer = bPtr;

                    ptrEnd = ptrBuffer + memsize;
                    while ((ptrBuffer + 4) <= ptrEnd)
                    {
                        hash = hash + Converters.ReadBytesAsUInt32LE((IntPtr)ptrBuffer, 0) * PRIME32_3;
                        hash = Bits.RotateLeft32(hash, 17) * PRIME32_4;
                        ptrBuffer += 4;
                    } // end while

                    while (ptrBuffer < ptrEnd)
                    {
                        hash = hash + (*ptrBuffer) * PRIME32_5;
                        hash = Bits.RotateLeft32(hash, 11) * PRIME32_1;
                        ptrBuffer++;
                    } // end while
                }
            }        

            hash = hash ^ (hash >> 15);
            hash = hash * PRIME32_2;
            hash = hash ^ (hash >> 13);
            hash = hash * PRIME32_3;
            hash = hash ^ (hash >> 16);

            IHashResult result = new HashResult(hash);

            Initialize();

            return result;
        } // end function TransformFinal

        virtual public Int32? KeyLength
	    {
            get
            {
                return 4;
            }
        } // end property KeyLength

        virtual public byte[] Key
	    {
            get
            {
                return Converters.ReadUInt32AsBytesLE(key);
            }
            set
            {
                if (!(value == null || value.Length == 0))
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
