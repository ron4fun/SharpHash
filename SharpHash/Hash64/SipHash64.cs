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

namespace SharpHash.Hash64
{
    internal abstract class SipHash : Hash, IHash64, IHashWithKey, ITransformBlock
    {
        protected UInt64 v0, v1, v2, v3, key0, key1, total_length, m;
        protected Int32 cr, fr, idx;
        protected byte[] buf = null;

        private static readonly UInt64 V0 = 0x736F6D6570736575;
        private static readonly UInt64 V1 = 0x646F72616E646F6D;
        private static readonly UInt64 V2 = 0x6C7967656E657261;
        private static readonly UInt64 V3 = 0x7465646279746573;
        private static readonly UInt64 KEY0 = 0x0706050403020100;
        private static readonly UInt64 KEY1 = 0x0F0E0D0C0B0A0908;

        static private readonly string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        public SipHash(Int32 hash_size, Int32 block_size)
            : base(hash_size, block_size)
        {
            key0 = KEY0;
            key1 = KEY1;
            Array.Resize(ref buf, 8);
        } // end constructor

        override public void Initialize()
        {
            v0 = V0;
            v1 = V1;
            v2 = V2;
            v3 = V3;
            total_length = 0;
            idx = 0;

            v3 = v3 ^ key1;
            v2 = v2 ^ key0;
            v1 = v1 ^ key1;
            v0 = v0 ^ key0;
        } // end function Initialize

        override public unsafe void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            Int32 i, iter, offset;

            i = a_index;

            total_length += (UInt32)a_length;

            fixed (byte* ptr_a_data = a_data, ptr_Fm_buf = buf)
            {
                // consume last pending bytes

                if ((idx != 0) && (a_length != 0))
                {
                    while ((idx < 8) && (a_length != 0))
                    {
                        buf[idx] = *(ptr_a_data + a_index);
                        idx++;
                        a_index++;
                        a_length--;
                    } // end while
                    if (idx == 8)
                    {
                        m = Converters.ReadBytesAsUInt64LE((IntPtr)ptr_Fm_buf, 0);
                        ProcessBlock(m);
                        idx = 0;
                    } // end if
                } // end if
                else
                {
                    i = 0;
                } // end else

                iter = a_length >> 3;

                // body

                while (i < iter)
                {
                    m = Converters.ReadBytesAsUInt64LE((IntPtr)ptr_a_data, a_index + (i * 8));
                    ProcessBlock(m);
                    i++;
                } // end while

                // save pending end bytes
                offset = a_index + (i * 8);

                while (offset < (a_length + a_index))
                {
                    ByteUpdate(a_data[offset]);
                    offset++;
                } // end while
            }
        } // end function TransformBytes

        override public IHashResult TransformFinal()
        {
            UInt64 finalBlock = ProcessFinalBlock();
            v3 ^= finalBlock;
            CompressTimes(cr);
            v0 ^= finalBlock;
            v2 ^= GetMagicXor();
            CompressTimes(fr);

            byte[] BufferByte = new byte[HashSize];
            Converters.ReadUInt64AsBytesLE(v0 ^ v1 ^ v2 ^ v3, ref BufferByte, 0);

            IHashResult result = new HashResult(BufferByte);

            Initialize();

            return result;
        } // end function TransformFinal

        protected abstract byte GetMagicXor();

        protected void Compress()
        {
            v0 = v0 + v1;
            v2 = v2 + v3;
            v1 = Bits.RotateLeft64(v1, 13);
            v3 = Bits.RotateLeft64(v3, 16);
            v1 = v1 ^ v0;
            v3 = v3 ^ v2;
            v0 = Bits.RotateLeft64(v0, 32);
            v2 = v2 + v1;
            v0 = v0 + v3;
            v1 = Bits.RotateLeft64(v1, 17);
            v3 = Bits.RotateLeft64(v3, 21);
            v1 = v1 ^ v2;
            v3 = v3 ^ v0;
            v2 = Bits.RotateLeft64(v2, 32);
        } // end function Compress

        protected void CompressTimes(Int32 a_times)
        {
            Int32 i = 0;

            while (i < a_times)
            {
                Compress();
                i++;
            } // end while
        } // end function CompressTimes

        protected void ProcessBlock(UInt64 a_m)
        {
            v3 = v3 ^ a_m;
            CompressTimes(cr);
            v0 = v0 ^ a_m;
        } // end function ProcessBlock

        protected unsafe void ByteUpdate(byte a_b)
        {
            buf[idx] = a_b;
            idx++;
            if (idx >= 8)
            {
                fixed (byte* ptr_Fm_buf = buf)
                {
                    UInt64 m = Converters.ReadBytesAsUInt64LE((IntPtr)ptr_Fm_buf, 0);
                    ProcessBlock(m);
                    idx = 0;
                }
            } // end if
        } // end function ByteUpdate

        protected void Finish()
        {
            UInt64 b = (UInt64)(total_length & 0xFF) << 56;

            if (idx != 0)
            {
                switch (idx)
                {
                    case 7:
                        b = b | ((UInt64)(buf[6]) << 48);
                        b = b | ((UInt64)(buf[5]) << 40);
                        b = b | ((UInt64)(buf[4]) << 32);
                        b = b | ((UInt64)(buf[3]) << 24);
                        b = b | ((UInt64)(buf[2]) << 16);
                        b = b | ((UInt64)(buf[1]) << 8);
                        b = b | ((UInt64)(buf[0]));
                        break;

                    case 6:
                        b = b | ((UInt64)(buf[5]) << 40);
                        b = b | ((UInt64)(buf[4]) << 32);
                        b = b | ((UInt64)(buf[3]) << 24);
                        b = b | ((UInt64)(buf[2]) << 16);
                        b = b | ((UInt64)(buf[1]) << 8);
                        b = b | ((UInt64)(buf[0]));
                        break;

                    case 5:
                        b = b | ((UInt64)(buf[4]) << 32);
                        b = b | ((UInt64)(buf[3]) << 24);
                        b = b | ((UInt64)(buf[2]) << 16);
                        b = b | ((UInt64)(buf[1]) << 8);
                        b = b | ((UInt64)(buf[0]));
                        break;

                    case 4:
                        b = b | ((UInt64)(buf[3]) << 24);
                        b = b | ((UInt64)(buf[2]) << 16);
                        b = b | ((UInt64)(buf[1]) << 8);
                        b = b | ((UInt64)(buf[0]));
                        break;

                    case 3:
                        b = b | ((UInt64)(buf[2]) << 16);
                        b = b | ((UInt64)(buf[1]) << 8);
                        b = b | ((UInt64)(buf[0]));
                        break;

                    case 2:
                        b = b | ((UInt64)(buf[1]) << 8);
                        b = b | ((UInt64)(buf[0]));
                        break;

                    case 1:
                        b = b | ((UInt64)(buf[0]));
                        break;
                } // end switch
            } // end if

            v3 = v3 ^ b;
            CompressTimes(cr);
            v0 = v0 ^ b;
            v2 = v2 ^ 0xFF;
            CompressTimes(fr);
        } // end function Finish

        protected UInt64 ProcessFinalBlock()
        {
            UInt64 result = (total_length & 0xFF) << 56;

            if (idx == 0) return result;
            switch (idx)
            {
                case 7:
                    result |= (UInt64)buf[6] << 48;
                    result |= (UInt64)buf[5] << 40;
                    result |= (UInt64)buf[4] << 32;
                    result |= (UInt64)buf[3] << 24;
                    result |= (UInt64)buf[2] << 16;
                    result |= (UInt64)buf[1] << 8;
                    result |= buf[0];
                    break;

                case 6:
                    result |= (UInt64)buf[5] << 40;
                    result |= (UInt64)buf[4] << 32;
                    result |= (UInt64)buf[3] << 24;
                    result |= (UInt64)buf[2] << 16;
                    result |= (UInt64)buf[1] << 8;
                    result |= buf[0];
                    break;

                case 5:
                    result |= (UInt64)buf[4] << 32;
                    result |= (UInt64)buf[3] << 24;
                    result |= (UInt64)buf[2] << 16;
                    result |= (UInt64)buf[1] << 8;
                    result |= buf[0];
                    break;

                case 4:
                    result |= (UInt64)buf[3] << 24;
                    result |= (UInt64)buf[2] << 16;
                    result |= (UInt64)buf[1] << 8;
                    result |= buf[0];
                    break;

                case 3:
                    result |= (UInt64)buf[2] << 16;
                    result |= (UInt64)buf[1] << 8;
                    result |= buf[0];
                    break;

                case 2:
                    result |= (UInt64)buf[1] << 8;
                    result |= buf[0];
                    break;

                case 1:
                    result |= buf[0];
                    break;
            }

            return result;
        }

        virtual public Int32? KeyLength
        {
            get => 16;
        } // end property KeyLength

        virtual public unsafe byte[] Key
        {
            get
            {
                byte[] LKey = new byte[(Int32)KeyLength];

                Converters.ReadUInt64AsBytesLE(key0, ref LKey, 0);
                Converters.ReadUInt64AsBytesLE(key1, ref LKey, 8);

                return LKey;
            }
            set
            {
                if (value == null || value.Length == 0)
                {
                    key0 = KEY0;
                    key1 = KEY1;
                } // end if
                else
                {
                    if (value.Length != KeyLength)
                        throw new ArgumentHashLibException(string.Format(InvalidKeyLength, KeyLength));

                    unsafe
                    {
                        fixed (byte* bPtr = &value[0])
                        {
                            key0 = Converters.ReadBytesAsUInt64LE((IntPtr)bPtr, 0);
                            key1 = Converters.ReadBytesAsUInt64LE((IntPtr)bPtr, 8);
                        }
                    }
                } // end else
            }
        } // end property Key

    } // end class SipHash

  
    internal class SipHash64 : SipHash
    {
        protected SipHash64(Int32 compression_rounds, Int32 finalization_rounds) 
            : base(8, 8)
        {
            cr = compression_rounds;
            fr = finalization_rounds;
        } // end constructor

        override public IHashResult TransformFinal()
        {
            UInt64 finalBlock = ProcessFinalBlock();
            v3 ^= finalBlock;
            CompressTimes(cr);
            v0 ^= finalBlock;
            v2 ^= GetMagicXor();
            CompressTimes(fr);

            byte[] BufferByte = new byte[HashSize];
            Converters.ReadUInt64AsBytesLE(v0 ^ v1 ^ v2 ^ v3, ref BufferByte, 0);

            IHashResult result = new HashResult(BufferByte);

            Initialize();

            return result;
        } // end function TransformFinal

        override protected byte GetMagicXor() => 0xFF;

    }; // end class SipHash64

    /// <summary>
    /// SipHash 2 - 4 algorithm.
    /// <summary>
    internal sealed class SipHash64_2_4 : SipHash64
    {
        public SipHash64_2_4()
            : base(2, 4)
        {} // end constructor

        public override IHash Clone()
        {
            SipHash64_2_4 HashInstance = new SipHash64_2_4();
            HashInstance.v0 = v0;
            HashInstance.v1 = v1;
            HashInstance.v2 = v2;
            HashInstance.v3 = v3;
            HashInstance.key0 = key0;
            HashInstance.key1 = key1;
            HashInstance.total_length = total_length;
            HashInstance.cr = cr;
            HashInstance.fr = fr;
            HashInstance.idx = idx;

            HashInstance.buf = buf.DeepCopy();

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

    } // end class SipHash64_2_4

}