using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Hash128
{
    internal sealed class MurmurHash3_x64_128 : Hash, IHash128, IHashWithKey, ITransformBlock
    {
        private UInt64 h1, h2, total_length;
        private UInt32 key;
        private Int32 idx;
        private byte[] buf = null;

        static private readonly UInt32 CKEY = 0x0;

        static private readonly UInt64 C1 = 0x87C37B91114253D5;
        static private readonly UInt64 C5 = 0xFF51AFD7ED558CCD;
        static private readonly UInt64 C6 = 0xC4CEB9FE1A85EC53;

        static private readonly UInt64 C2 = 0x4CF5AD432745937F;
        static private readonly UInt32 C3 = 0x52DCE729;
        static private readonly UInt32 C4 = 0x38495AB5;      

        static private readonly string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        public MurmurHash3_x64_128()
          : base(16, 16)
        {
            key = CKEY;
            buf = new byte[16];
        } // end constructor

        override public IHash Clone()
        {
            MurmurHash3_x64_128 HashInstance = new MurmurHash3_x64_128();
            HashInstance.h1 = h1;
            HashInstance.h2 = h2;
            HashInstance.total_length = total_length;
            HashInstance.key = key;
            HashInstance.idx = idx;

            if (!(buf == null || buf.Length == 0))
            {
                HashInstance.buf = new byte[buf.Length];
                Utils.Utils.memcopy(ref HashInstance.buf, buf, buf.Length);
            } // end if

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public void Initialize()
        {
            h1 = key;
            h2 = key;

            total_length = 0;
            idx = 0;
        } // end function Initialize

        override public unsafe IHashResult TransformFinal()
        {
            Finish();

            UInt64[] tempBufUInt64 = new UInt64[] { h1, h2 };
            byte[] tempBufByte = new byte[tempBufUInt64.Length * sizeof(UInt64)];

            fixed (UInt64* tmpPtr = tempBufUInt64)
            {
                fixed (byte* bPtr = tempBufByte)
                {
                    Converters.be64_copy((IntPtr)tmpPtr, 0, (IntPtr)bPtr, 0, tempBufByte.Length);

                    IHashResult result = new HashResult(tempBufByte);

                    Initialize();

                    return result;
                }
            }

        } // end function TransformFinal

        override public unsafe void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            Int32 len, nBlocks, i, offset, lIdx;
            UInt64 k1, k2;

            len = a_length;
            i = a_index;
            lIdx = 0;
            total_length += (UInt32)len;
            
            fixed(byte* ptr_a_data = a_data)
            {
                //consume last pending bytes
                if (idx != 0 && a_length != 0)
                {
                    while (idx < 16 && len != 0)
                    {
                        buf[idx++] = *(ptr_a_data + a_index);
                        a_index++;
                        len--;
                    }

                    if (idx == 16)
                        ProcessPendings();
                }
                else
                    i = 0;

                nBlocks = len >> 4;

                // body
                while (i < nBlocks)
                {
                    k1 = Converters.ReadBytesAsUInt64LE((IntPtr)ptr_a_data, a_index + lIdx);
                    lIdx += 8;

                    k2 = Converters.ReadBytesAsUInt64LE((IntPtr)ptr_a_data, a_index + lIdx);
                    lIdx += 8;

                    k1 = k1 * C1;
                    k1 = Bits.RotateLeft64(k1, 31);
                    k1 = k1 * C2;
                    h1 = h1 ^ k1;

                    h1 = Bits.RotateLeft64(h1, 27);
                    h1 = h1 + h2;
                    h1 = h1 * 5 + C3;

                    k2 = k2 * C2;
                    k2 = Bits.RotateLeft64(k2, 33);
                    k2 = k2 * C1;
                    h2 = h2 ^ k2;

                    h2 = Bits.RotateLeft64(h2, 31);
                    h2 = h2 + h1;
                    h2 = h2 * 5 + C4;

                    i++;
                } // end if

                offset = a_index + (i * 16);
                while (offset < (a_index + len))
                {
                    ByteUpdate(a_data[offset]);
                    offset++;
                } // end while
            }

        } // end function TransformBytes

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
                        throw new ArgumentHashLibException(string.Format(InvalidKeyLength, KeyLength));

                    unsafe
                    {
                        fixed (byte* bPtr = value)
                        {
                            key = Converters.ReadBytesAsUInt32LE((IntPtr)bPtr, 0);
                        }
                    }

                } // end else
            }

        } // end property Key

        private void ByteUpdate(byte a_b)
	    {
            buf[idx++] = a_b;
            ProcessPendings();
        } // end function ByteUpdate

        private unsafe void ProcessPendings()
        {
            UInt64 k1, k2;

            fixed (byte* ptr_Fm_buf = buf)
            {
                if (idx >= 16)
                {
                    k1 = Converters.ReadBytesAsUInt64LE((IntPtr)ptr_Fm_buf, 0);
                    k2 = Converters.ReadBytesAsUInt64LE((IntPtr)ptr_Fm_buf, 8);

                    k1 = k1 * C1;
                    k1 = Bits.RotateLeft64(k1, 31);
                    k1 = k1 * C2;
                    h1 = h1 ^ (UInt32)k1;

                    h1 = (UInt32)Bits.RotateLeft64(h1, 27);
                    h1 = h1 + h2;
                    h1 = h1 * 5 + C3;

                    k2 = k2 * C2;
                    k2 = (UInt32)Bits.RotateLeft64(k2, 33);
                    k2 = k2 * C1;
                    h2 = h2 ^ (UInt32)k2;

                    h2 = (UInt32)Bits.RotateLeft64(h2, 31);
                    h2 = h2 + h1;
                    h2 = h2 * 5 + C4;

                    idx = 0;
                } // end if
            }

        } // end function ProcessPendings

        private unsafe void Finish()
        {
            UInt64 k1, k2;
            Int32 Length;

            // tail
            k1 = 0;
            k2 = 0;

            Length = idx;
            if (Length != 0)
            {
                switch (Length)
                {
                    case 15:
                        k2 = k2 ^ ((UInt64)buf[14] << 48);
                        k2 = k2 ^ ((UInt64)buf[13] << 40);
                        k2 = k2 ^ ((UInt64)buf[12] << 32);
                        k2 = k2 ^ ((UInt64)buf[11] << 24);
                        k2 = k2 ^ ((UInt64)buf[10] << 16);
                        k2 = k2 ^ ((UInt64)buf[9] << 8);
                        k2 = k2 ^ ((UInt64)buf[8] << 0);
                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 = k2 * C1;
                        h2 = h2 ^ k2;
                        break;

                    case 14:
                        k2 = k2 ^ ((UInt64)buf[13] << 40);
                        k2 = k2 ^ ((UInt64)buf[12] << 32);
                        k2 = k2 ^ ((UInt64)buf[11] << 24);
                        k2 = k2 ^ ((UInt64)buf[10] << 16);
                        k2 = k2 ^ ((UInt64)buf[9] << 8);
                        k2 = k2 ^ ((UInt64)buf[8] << 0);
                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 = k2 * C1;
                        h2 = h2 ^ k2;
                        break;

                    case 13:
                        k2 = k2 ^ ((UInt64)buf[12] << 32);
                        k2 = k2 ^ ((UInt64)buf[11] << 24);
                        k2 = k2 ^ ((UInt64)buf[10] << 16);
                        k2 = k2 ^ ((UInt64)buf[9] << 8);
                        k2 = k2 ^ ((UInt64)buf[8] << 0);
                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 = k2 * C1;
                        h2 = h2 ^ k2;
                        break;

                    case 12:
                        k2 = k2 ^ ((UInt64)buf[11] << 24);
                        k2 = k2 ^ ((UInt64)buf[10] << 16);
                        k2 = k2 ^ ((UInt64)buf[9] << 8);
                        k2 = k2 ^ ((UInt64)buf[8] << 0);
                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 = k2 * C1;
                        h2 = h2 ^ k2;
                        break;

                    case 11:
                        k2 = k2 ^ ((UInt64)buf[10] << 16);
                        k2 = k2 ^ ((UInt64)buf[9] << 8);
                        k2 = k2 ^ ((UInt64)buf[8] << 0);
                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 = k2 * C1;
                        h2 = h2 ^ k2;
                        break;

                    case 10:
                        k2 = k2 ^ ((UInt64)buf[9] << 8);
                        k2 = k2 ^ ((UInt64)buf[8] << 0);
                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 = k2 * C1;
                        h2 = h2 ^ k2;
                        break;

                    case 9:
                        k2 = k2 ^ ((UInt64)buf[8] << 0);
                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 = k2 * C1;
                        h2 = h2 ^ k2;
                        break;
                } // end switch

                if (Length > 8)
                    Length = 8;

                switch (Length)
                {
                    case 8:
                        k1 = k1 ^ ((UInt64)buf[7] << 56);
                        k1 = k1 ^ ((UInt64)buf[6] << 48);
                        k1 = k1 ^ ((UInt64)buf[5] << 40);
                        k1 = k1 ^ ((UInt64)buf[4] << 32);
                        k1 = k1 ^ ((UInt64)buf[3] << 24);
                        k1 = k1 ^ ((UInt64)buf[2] << 16);
                        k1 = k1 ^ ((UInt64)buf[1] << 8);
                        k1 = k1 ^ ((UInt64)buf[0] << 0);
                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                    case 7:
                        k1 = k1 ^ ((UInt64)buf[6] << 48);
                        k1 = k1 ^ ((UInt64)buf[5] << 40);
                        k1 = k1 ^ ((UInt64)buf[4] << 32);
                        k1 = k1 ^ ((UInt64)buf[3] << 24);
                        k1 = k1 ^ ((UInt64)buf[2] << 16);
                        k1 = k1 ^ ((UInt64)buf[1] << 8);
                        k1 = k1 ^ ((UInt64)buf[0] << 0);
                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                    case 6:
                        k1 = k1 ^ ((UInt64)buf[5] << 40);
                        k1 = k1 ^ ((UInt64)buf[4] << 32);
                        k1 = k1 ^ ((UInt64)buf[3] << 24);
                        k1 = k1 ^ ((UInt64)buf[2] << 16);
                        k1 = k1 ^ ((UInt64)buf[1] << 8);
                        k1 = k1 ^ ((UInt64)buf[0] << 0);
                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                    case 5:
                        k1 = k1 ^ ((UInt64)buf[4] << 32);
                        k1 = k1 ^ ((UInt64)buf[3] << 24);
                        k1 = k1 ^ ((UInt64)buf[2] << 16);
                        k1 = k1 ^ ((UInt64)buf[1] << 8);
                        k1 = k1 ^ ((UInt64)buf[0] << 0);
                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                    case 4:
                        k1 = k1 ^ ((UInt64)buf[3] << 24);
                        k1 = k1 ^ ((UInt64)buf[2] << 16);
                        k1 = k1 ^ ((UInt64)buf[1] << 8);
                        k1 = k1 ^ ((UInt64)buf[0] << 0);
                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                    case 3:
                        k1 = k1 ^ ((UInt64)buf[2] << 16);
                        k1 = k1 ^ ((UInt64)buf[1] << 8);
                        k1 = k1 ^ ((UInt64)buf[0] << 0);
                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                    case 2:
                        k1 = k1 ^ ((UInt64)buf[1] << 8);
                        k1 = k1 ^ ((UInt64)buf[0] << 0);
                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                    case 1:
                        k1 = k1 ^ ((UInt64)buf[0] << 0);
                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                } // end switch

            } // end if

            // finalization

            h1 = h1 ^ total_length;
            h2 = h2 ^ total_length;

            h1 = h1 + h2;
            h2 = h2 + h1;

            h1 = h1 ^ (h1 >> 33);
            h1 = h1 * C5;
            h1 = h1 ^ (h1 >> 33);
            h1 = h1 * C6;
            h1 = h1 ^ (h1 >> 33);

            h2 = h2 ^ (h2 >> 33);
            h2 = h2 * C5;
            h2 = h2 ^ (h2 >> 33);
            h2 = h2 * C6;
            h2 = h2 ^ (h2 >> 33);

            h1 = h1 + h2;
            h2 = h2 + h1;

        } // end function Finish

    } // end class MurmurHash3_x64_128

}
