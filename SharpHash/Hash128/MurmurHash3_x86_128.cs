using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace SharpHash.Hash128
{
    internal sealed class MurmurHash3_x86_128 : Hash, IHash128, IHashWithKey, ITransformBlock
    {
        private UInt32 key, h1, h2, h3, h4, total_length;
        private Int32 idx;
        byte[] buf = null;

        static private readonly UInt32 CKEY = 0x0;

        static private readonly UInt32 C1 = 0x239B961B;
        static private readonly UInt32 C2 = 0xAB0E9789;
        static private readonly UInt32 C3 = 0x38B34AE5;
        static private readonly UInt32 C4 = 0xA1E38B93;
        static private readonly UInt32 C5 = 0x85EBCA6B;
        static private readonly UInt32 C6 = 0xC2B2AE35;

        static private readonly UInt32 C7 = 0x561CCD1B;
        static private readonly UInt32 C8 = 0x0BCAA747;
        static private readonly UInt32 C9 = 0x96CD1C35;
        static private readonly UInt32 C10 = 0x32AC3B17;

        static private readonly string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        public MurmurHash3_x86_128()
          : base(16, 16)
        {
            key = CKEY;
            buf = new byte[16];
        } // end constructor

        override public IHash Clone()
        {
            MurmurHash3_x86_128 HashInstance = new MurmurHash3_x86_128();
            HashInstance.key = key;
            HashInstance.h1 = h1;
            HashInstance.h2 = h2;
            HashInstance.h3 = h3;
            HashInstance.h4 = h4;
            HashInstance.total_length = total_length;
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
            h3 = key;
            h4 = key;

            total_length = 0;
            idx = 0;
        } // end function Initialize

        override public unsafe IHashResult TransformFinal()
        {
            Finish();

            UInt32[] tempBufUInt32 = new UInt32[] { h1, h2, h3, h4 };
            byte[] tempBufByte = new byte[tempBufUInt32.Length * sizeof(UInt32)];

            fixed (UInt32* tmpPtr = tempBufUInt32)
            {
                fixed (byte* bPtr = tempBufByte)
                {
                    Converters.be32_copy((IntPtr)tmpPtr, 0, (IntPtr)bPtr, 0, tempBufByte.Length);

                    IHashResult result = new HashResult(tempBufByte);

                    Initialize();

                    return result;
                }
            }

        } // end function TransformFinal

        override public unsafe void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            Int32 len, nBlocks, i, offset, lIdx;
            UInt32 k1, k2, k3, k4;

            len = a_length;
            i = a_index;
            lIdx = 0;
            total_length += (UInt32)len;
            
            fixed(byte* ptr_a_data = a_data)
            {
                //consume last pending bytes
                if (idx != 0 && len != 0)
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
                    k1 = Converters.ReadBytesAsUInt32LE((IntPtr)ptr_a_data, a_index + lIdx);
                    lIdx += 4;
                    k2 = Converters.ReadBytesAsUInt32LE((IntPtr)ptr_a_data, a_index + lIdx);
                    lIdx += 4;
                    k3 = Converters.ReadBytesAsUInt32LE((IntPtr)ptr_a_data, a_index + lIdx);
                    lIdx += 4;
                    k4 = Converters.ReadBytesAsUInt32LE((IntPtr)ptr_a_data, a_index + lIdx);
                    lIdx += 4;

                    k1 = k1 * C1;
                    k1 = Bits.RotateLeft32(k1, 15);
                    k1 = k1 * C2;
                    h1 = h1 ^ k1;

                    h1 = Bits.RotateLeft32(h1, 19);

                    h1 = h1 + h2;
                    h1 = h1 * 5 + C7;

                    k2 = k2 * C2;
                    k2 = Bits.RotateLeft32(k2, 16);
                    k2 = k2 * C3;
                    h2 = h2 ^ k2;

                    h2 = Bits.RotateLeft32(h2, 17);

                    h2 = h2 + h3;
                    h2 = h2 * 5 + C8;

                    k3 = k3 * C3;
                    k3 = Bits.RotateLeft32(k3, 17);
                    k3 = k3 * C4;
                    h3 = h3 ^ k3;

                    h3 = Bits.RotateLeft32(h3, 15);

                    h3 = h3 + h4;
                    h3 = h3 * 5 + C9;

                    k4 = k4 * C4;
                    k4 = Bits.RotateLeft32(k4, 18);
                    k4 = k4 * C1;
                    h4 = h4 ^ k4;

                    h4 = Bits.RotateLeft32(h4, 13);

                    h4 = h4 + h1;
                    h4 = h4 * 5 + C10;

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
                        fixed (byte* bPtr = &value[0])
                        {
                            key = Converters.ReadBytesAsUInt32LE((IntPtr)bPtr, 0);
                        }
                    }

                } // end else
            }

        } // end property Key

        private void ByteUpdate(byte a_b)
	    {
            buf[idx] = a_b;
		    idx++;
            ProcessPendings();
        } // end function ByteUpdate

        private unsafe void ProcessPendings()
        {
            UInt32 k1, k2, k3, k4;

            fixed (byte* ptr_Fm_buf = buf)
            {
                if (idx >= 16)
                {
                    
                    k1 = Converters.ReadBytesAsUInt32LE((IntPtr)ptr_Fm_buf, 0);
                    k2 = Converters.ReadBytesAsUInt32LE((IntPtr)ptr_Fm_buf, 4);
                    k3 = Converters.ReadBytesAsUInt32LE((IntPtr)ptr_Fm_buf, 8);
                    k4 = Converters.ReadBytesAsUInt32LE((IntPtr)ptr_Fm_buf, 12);

                    k1 = k1 * C1;
                    k1 = Bits.RotateLeft32(k1, 15);
                    k1 = k1 * C2;
                    h1 = h1 ^ k1;

                    h1 = Bits.RotateLeft32(h1, 19);

                    h1 = h1 + h2;
                    h1 = h1 * 5 + C7;

                    k2 = k2 * C2;
                    k2 = Bits.RotateLeft32(k2, 16);
                    k2 = k2 * C3;
                    h2 = h2 ^ k2;

                    h2 = Bits.RotateLeft32(h2, 17);

                    h2 = h2 + h3;
                    h2 = h2 * 5 + C8;

                    k3 = k3 * C3;
                    k3 = Bits.RotateLeft32(k3, 17);
                    k3 = k3 * C4;
                    h3 = h3 ^ k3;

                    h3 = Bits.RotateLeft32(h3, 15);

                    h3 = h3 + h4;
                    h3 = h3 * 5 + C9;

                    k4 = k4 * C4;
                    k4 = Bits.RotateLeft32(k4, 18);
                    k4 = k4 * C1;
                    h4 = h4 ^ k4;

                    h4 = Bits.RotateLeft32(h4, 13);

                    h4 = h4 + h1;
                    h4 = h4 * 5 + C10;

                    idx = 0;
                } // end if
            }

        } // end function ProcessPendings

        private unsafe void Finish()
        {
            UInt32 k1, k2, k3, k4;
            Int32 Length;

            // tail
            k1 = 0;
            k2 = 0;
            k3 = 0;
            k4 = 0;

            Length = idx;
            if (Length != 0)
            {
                switch (Length)
                {
                    case 15:
                        k4 = k4 ^ (UInt32)(buf[14] << 16);
                        k4 = k4 ^ (UInt32)(buf[13] << 8);
                        k4 = k4 ^ (UInt32)(buf[12] << 0);

                        k4 = k4 * C4;
                        k4 = Bits.RotateLeft32(k4, 18);
                        k4 = k4 * C1;
                        h4 = h4 ^ k4;
                        break;

                    case 14:
                        k4 = k4 ^ (UInt32)(buf[13] << 8);
                        k4 = k4 ^ (UInt32)(buf[12] << 0);
                        k4 = k4 * C4;
                        k4 = Bits.RotateLeft32(k4, 18);
                        k4 = k4 * C1;
                        h4 = h4 ^ k4;
                        break;

                    case 13:
                        k4 = k4 ^ (UInt32)(buf[12] << 0);
                        k4 = k4 * C4;
                        k4 = Bits.RotateLeft32(k4, 18);
                        k4 = k4 * C1;
                        h4 = h4 ^ k4;
                        break;
                } // end switch

                if (Length > 12)
                    Length = 12;

                switch (Length)
                {
                    case 12:
                        k3 = k3 ^ (UInt32)(buf[11] << 24);
                        k3 = k3 ^ (UInt32)(buf[10] << 16);
                        k3 = k3 ^ (UInt32)(buf[9] << 8);
                        k3 = k3 ^ (UInt32)(buf[8] << 0);

                        k3 = k3 * C3;
                        k3 = Bits.RotateLeft32(k3, 17);
                        k3 = k3 * C4;
                        h3 = h3 ^ k3;
                        break;

                    case 11:
                        k3 = k3 ^ (UInt32)(buf[10] << 16);
                        k3 = k3 ^ (UInt32)(buf[9] << 8);
                        k3 = k3 ^ (UInt32)(buf[8] << 0);

                        k3 = k3 * C3;
                        k3 = Bits.RotateLeft32(k3, 17);
                        k3 = k3 * C4;
                        h3 = h3 ^ k3;
                        break;

                    case 10:
                        k3 = k3 ^ (UInt32)(buf[9] << 8);
                        k3 = k3 ^ (UInt32)(buf[8] << 0);

                        k3 = k3 * C3;
                        k3 = Bits.RotateLeft32(k3, 17);
                        k3 = k3 * C4;
                        h3 = h3 ^ k3;
                        break;

                    case 9:
                        k3 = k3 ^ (UInt32)(buf[8] << 0);

                        k3 = k3 * C3;
                        k3 = Bits.RotateLeft32(k3, 17);
                        k3 = k3 * C4;
                        h3 = h3 ^ k3;
                        break;

                } // end switch

                if (Length > 8)
                    Length = 8;

                switch (Length)
                {
                    case 8:
                        k2 = k2 ^ (UInt32)(buf[7] << 24);
                        k2 = k2 ^ (UInt32)(buf[6] << 16);
                        k2 = k2 ^ (UInt32)(buf[5] << 8);
                        k2 = k2 ^ (UInt32)(buf[4] << 0);

                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft32(k2, 16);
                        k2 = k2 * C3;
                        h2 = h2 ^ k2;
                        break;

                    case 7:
                        k2 = k2 ^ (UInt32)(buf[6] << 16);
                        k2 = k2 ^ (UInt32)(buf[5] << 8);
                        k2 = k2 ^ (UInt32)(buf[4] << 0);

                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft32(k2, 16);
                        k2 = k2 * C3;
                        h2 = h2 ^ k2;
                        break;

                    case 6:
                        k2 = k2 ^ (UInt32)(buf[5] << 8);
                        k2 = k2 ^ (UInt32)(buf[4] << 0);

                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft32(k2, 16);
                        k2 = k2 * C3;
                        h2 = h2 ^ k2;
                        break;

                    case 5:
                        k2 = k2 ^ (UInt32)(buf[4] << 0);

                        k2 = k2 * C2;
                        k2 = Bits.RotateLeft32(k2, 16);
                        k2 = k2 * C3;
                        h2 = h2 ^ k2;
                        break;

                } // end switch

                if (Length > 4)
                    Length = 4;

                switch (Length)
                {
                    case 4:
                        k1 = k1 ^ (UInt32)(buf[3] << 24);
                        k1 = k1 ^ (UInt32)(buf[2] << 16);
                        k1 = k1 ^ (UInt32)(buf[1] << 8);
                        k1 = k1 ^ (UInt32)(buf[0] << 0);

                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft32(k1, 15);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                    case 3:
                        k1 = k1 ^ (UInt32)(buf[2] << 16);
                        k1 = k1 ^ (UInt32)(buf[1] << 8);
                        k1 = k1 ^ (UInt32)(buf[0] << 0);

                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft32(k1, 15);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                    case 2:
                        k1 = k1 ^ (UInt32)(buf[1] << 8);
                        k1 = k1 ^ (UInt32)(buf[0] << 0);

                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft32(k1, 15);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                    case 1:
                        k1 = k1 ^ (UInt32)(buf[0] << 0);

                        k1 = k1 * C1;
                        k1 = Bits.RotateLeft32(k1, 15);
                        k1 = k1 * C2;
                        h1 = h1 ^ k1;
                        break;

                } // end switch
            } // end if

            // finalization

            h1 = h1 ^ total_length;
            h2 = h2 ^ total_length;
            h3 = h3 ^ total_length;
            h4 = h4 ^ total_length;

            h1 = h1 + h2;
            h1 = h1 + h3;
            h1 = h1 + h4;
            h2 = h2 + h1;
            h3 = h3 + h1;
            h4 = h4 + h1;

            h1 = h1 ^ (h1 >> 16);
            h1 = h1 * C5;
            h1 = h1 ^ (h1 >> 13);
            h1 = h1 * C6;
            h1 = h1 ^ (h1 >> 16);

            h2 = h2 ^ (h2 >> 16);
            h2 = h2 * C5;
            h2 = h2 ^ (h2 >> 13);
            h2 = h2 * C6;
            h2 = h2 ^ (h2 >> 16);

            h3 = h3 ^ (h3 >> 16);
            h3 = h3 * C5;
            h3 = h3 ^ (h3 >> 13);
            h3 = h3 * C6;
            h3 = h3 ^ (h3 >> 16);

            h4 = h4 ^ (h4 >> 16);
            h4 = h4 * C5;
            h4 = h4 ^ (h4 >> 13);
            h4 = h4 * C6;
            h4 = h4 ^ (h4 >> 16);

            h1 = h1 + h2;
            h1 = h1 + h3;
            h1 = h1 + h4;
            h2 = h2 + h1;
            h3 = h3 + h1;
            h4 = h4 + h1;
        } // end function Finish

    } // end class MurmurHash3_x86_128

}
