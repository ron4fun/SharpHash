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

        public SipHash(Int32 a_compression_rounds = 2, Int32 a_finalization_rounds = 4)
            : base(8, 8)
        {
            key0 = KEY0;
            key1 = KEY1;
            cr = a_compression_rounds;
            fr = a_finalization_rounds;
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
            Int32 i, Length, iter, offset;
            
            Length = a_length;
            i = a_index;

            total_length += (UInt32)Length;

            fixed (byte* ptr_a_data = a_data, ptr_Fm_buf = buf)
            {
                // consume last pending bytes

                if ((idx != 0) && (a_length != 0))
                {
                    while ((idx < 8) && (Length != 0))
                    {
                        buf[idx] = *(ptr_a_data + a_index);
                        idx++;
                        a_index++;
                        Length--;
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

                iter = Length >> 3;

                // body

                while (i < iter)
                {
                    m = Converters.ReadBytesAsUInt64LE((IntPtr)ptr_a_data, a_index + (i * 8));
                    ProcessBlock(m);
                    i++;
                } // end while

                // save pending end bytes
                offset = a_index + (i * 8);

                while (offset < (Length + a_index))
                {
                    ByteUpdate(a_data[offset]);
                    offset++;
                } // end while

            }

        } // end function TransformBytes

        override public IHashResult TransformFinal()
        {
            Finish();

            IHashResult result = new HashResult(v0 ^ v1 ^ v2 ^ v3);

            Initialize();

            return result;
        } // end function TransformFinal

        private void Compress()
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

        private void CompressTimes(Int32 a_times)
	    {
            Int32 i = 0;
		
		    while (i < a_times)
		    {
			    Compress();
                i++;
		    } // end while
        } // end function CompressTimes

        private void ProcessBlock(UInt64 a_m)
        {
            v3 = v3 ^ a_m;
            CompressTimes(cr);
            v0 = v0 ^ a_m;
        } // end function ProcessBlock

        private unsafe void ByteUpdate(byte a_b)
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

        private void Finish()
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

        virtual public Int32? KeyLength
        {
            get
            {
                return 16;
            }
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

    /// <summary>
    /// SipHash 2 - 4 algorithm.
    /// <summary>
    internal class SipHash2_4 : SipHash
    {
        public SipHash2_4() : base(2, 4)
        { } // end constructor

        public override IHash Clone()
	    {
            SipHash2_4 HashInstance = new SipHash2_4();
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

            if (!(buf == null || buf.Length == 0))
            {
                HashInstance.buf = new byte[buf.Length];
                for (Int32 i = 0; i < buf.Length; i++)
                    HashInstance.buf[i] = buf[i];
            } // end if

            HashInstance.BufferSize = BufferSize;

		    return HashInstance;
	    } // end function Clone

    }; // end class SipHash2_4

}
