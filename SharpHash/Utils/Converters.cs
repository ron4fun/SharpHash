using SharpHash.Utils;
using System;

namespace SharpHash.Utils
{
    public static class Converters
    {
        public static void toUpper(IntPtr value, Int32 length)
	    {
		    for (int i = 0; i < length; i++)
		    {
                unsafe
                {
                    char c = (char)((byte*)value)[i];

                    ((byte*)value)[i] = (byte)char.ToLower(c);
                }
            } // end for

        } // end function toUpper

        public static void swap_copy_str_to_u32(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
        {
            unsafe
            {
                UInt32* lsrc, ldest, lend;
                byte* lbsrc;
                Int32 lLength;

                // if all pointers and length are 32-bits aligned
                if ((((int)((byte*)(dest) - (byte*)(0)) | (int)((byte*)(src) - (byte*)(0)) | src_index |
                    dest_index | length) & 3) == 0)
                {
                    // copy memory as 32-bit words
                    lsrc = (UInt32*)((byte*)(src) + src_index);
                    lend = (UInt32*)(((byte*)(src) + src_index) + length);
                    ldest = (UInt32*)((byte*)(dest) + dest_index);
                    while (lsrc < lend)
                    {
                        *ldest = Bits.ReverseBytesUInt32(*lsrc);
                        ldest += 1;
                        lsrc += 1;
                    } // end while
                } // end if

                else
                {
                    lbsrc = ((byte*)(src) + src_index);

                    lLength = length + dest_index;
                    while (dest_index < lLength)
                    {
                        ((byte*)dest)[dest_index ^ 3] = *lbsrc;

                        lbsrc += 1;
                        dest_index += 1;
                    } // end while
                } // end else
            }
        } // end function swap_copy_str_to_u32

        public static unsafe void swap_copy_str_to_u64(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
        {
            UInt64* lsrc, ldest, lend;
            byte* lbsrc;
            Int32 lLength;

            // if all pointers and length are 64-bits aligned
            if ((((Int32)((byte*)dest - (byte*)0) | (Int32)((byte*)src - (byte*)0) | src_index |
                dest_index | length) & 7) == 0)
            {
                // copy aligned memory block as 64-bit integers
                lsrc = (UInt64*)((byte*)src + src_index);
                lend = (UInt64*)(((byte*)src + src_index) + length);
                ldest = (UInt64*)((byte*)dest + dest_index);
                while (lsrc < lend)
                {
                    *ldest = Bits.ReverseBytesUInt64(*lsrc);
                    ldest += 1;
                    lsrc += 1;
                } // end while
            } // end if
            else
            {
                lbsrc = ((byte*)src + src_index);

                lLength = length + dest_index;
                while (dest_index < lLength)
                {
                    ((byte*)dest)[dest_index ^ 7] = *lbsrc;

                    lbsrc += 1;
                    dest_index += 1;
                } // end while				
            } // end else		
            
        } // end function swap_copy_str_to_u64
	
	    public static UInt32 be2me_32(UInt32 x)
        {
            if (BitConverter.IsLittleEndian)
            {
                return Bits.ReverseBytesUInt32(x);
            } // end if

            return x;
        } // end function be2me_32

        public static UInt64 be2me_64(UInt64 x)
        {
            if (BitConverter.IsLittleEndian)
            {
                return Bits.ReverseBytesUInt64(x);
            } // end if

            return x;
        } // end function be2me_64

        public static void be32_copy(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
        {
            if (BitConverter.IsLittleEndian)
            {
                Converters.swap_copy_str_to_u32(src, src_index, dest, dest_index, length);
            } // end if	
            else
            {
                unsafe
                {
                    Utils.memmove((IntPtr)(((byte*)dest) + dest_index), (IntPtr)(((byte*)src) + src_index), length);   
                }
            } // end else
        } // end function be32_copy

        public static void be64_copy(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
        {
            if (BitConverter.IsLittleEndian)
            {
                Converters.swap_copy_str_to_u64(src, src_index, dest, dest_index, length);
            } // end if	
            else
            {
                unsafe
                {
                    Utils.memmove((IntPtr)((byte*)dest + dest_index), (IntPtr)((byte*)src + src_index), length);
                }
            } // end else
        } // end function be64_copy

        public static UInt32 le2me_32(Int32 x)
        {
            if (!BitConverter.IsLittleEndian)
            {
                return Bits.ReverseBytesUInt32((UInt32)(x));
            } // end if

            return (UInt32)x;
        } // end function le2me_32

        public static UInt64 le2me_64(UInt64 x)
        {
            if (!BitConverter.IsLittleEndian)
            {
                return Bits.ReverseBytesUInt64(x);
            } // end if

            return x;
        } // end function le2me_64

        public static void le32_copy(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
        {
            if (BitConverter.IsLittleEndian)
            {
                unsafe
                {
                    Utils.memmove((IntPtr)((byte*)(dest) + dest_index), (IntPtr)((byte*)(src) + src_index), length);
                }
            } // end if
            else
            {
                Converters.swap_copy_str_to_u32(src, src_index, dest, dest_index, length);
            } // end else
        } // end function le32_copy

        public static void le64_copy(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
        {
            if (BitConverter.IsLittleEndian)
            {
                unsafe
                {
                    Utils.memmove((IntPtr)((byte*)(dest) + dest_index), (IntPtr)((byte*)(src) + src_index), length);
                }
            } // end if
            else
            {
                Converters.swap_copy_str_to_u64(src, src_index, dest, dest_index, length);
            } // end else
        } // end function le64_copy

        public static UInt32 ReadBytesAsUInt32LE(IntPtr a_in, Int32 a_index)
        {
            unsafe
            {
                UInt32 result = *(UInt32*)((byte*)a_in + a_index);
                return Converters.le2me_32((Int32)result);
            }            
        } // end function ReadBytesAsUInt32LE

        public static UInt64 ReadBytesAsUInt64LE(IntPtr a_in, Int32 a_index)
        {
            unsafe
            {
                UInt64 result = *(UInt64*)((byte*)a_in + a_index);
                return Converters.le2me_64(result);
            }
        } // end function ReadBytesAsUInt64LE

        public static byte[] ReadUInt32AsBytesLE(UInt32 a_in)
        {
            byte[] arr = new byte[4];
            arr[0] = (byte)(a_in);
            arr[1] = (byte)(a_in >> 8);
            arr[2] = (byte)(a_in >> 16);
            arr[3] = (byte)(a_in >> 24);

            return arr;
        } // end function ReadUInt32AsBytesLE

        public static byte[] ReadUInt64AsBytesLE(UInt64 a_in)
        {
            byte[] arr = new byte[8];
            arr[0] = (byte)(a_in);
            arr[1] = (byte)(a_in >> 8);
            arr[2] = (byte)(a_in >> 16);
            arr[3] = (byte)(a_in >> 24);
            arr[4] = (byte)(a_in >> 32);
            arr[5] = (byte)(a_in >> 40);
            arr[6] = (byte)(a_in >> 48);
            arr[7] = (byte)(a_in >> 56);

            return arr;
        } // end function ReadUInt64AsBytesLE

        public static void ReadUInt64AsBytesLE(UInt64 a_in, ref byte[] a_out, Int32 a_index)
        {
            a_out[a_index] = (byte)a_in;
            a_out[a_index + 1] = (byte)(a_in >> 8);
            a_out[a_index + 2] = (byte)(a_in >> 16);
            a_out[a_index + 3] = (byte)(a_in >> 24);
            a_out[a_index + 4] = (byte)(a_in >> 32);
            a_out[a_index + 5] = (byte)(a_in >> 40);
            a_out[a_index + 6] = (byte)(a_in >> 48);
            a_out[a_index + 7] = (byte)(a_in >> 56);
        } // end function ReadUInt64AsBytesLE

        public static void ReadUInt64AsBytesBE(UInt64 a_in, ref byte[] a_out, Int32 a_index)
        {
            a_out[a_index] = (byte)(a_in >> 56);
            a_out[a_index + 1] = (byte)(a_in >> 48);
            a_out[a_index + 2] = (byte)(a_in >> 40);
            a_out[a_index + 3] = (byte)(a_in >> 32);
            a_out[a_index + 4] = (byte)(a_in >> 24);
            a_out[a_index + 5] = (byte)(a_in >> 16);
            a_out[a_index + 6] = (byte)(a_in >> 8);
            a_out[a_index + 7] = (byte)a_in;
        } // end function ReadUInt64AsBytesBE

        public static string ConvertBytesToHexString(byte[] a_in, bool a_group)
        {
            if (a_in == null || a_in.Length == 0) return "";

            unsafe
            {
                fixed (byte* bPtr = a_in)
                {
                    return ConvertBytesToHexString((IntPtr)bPtr, (UInt32)a_in.Length, a_group);
                }
            }
        } // end function ConvertBytesToHexString

        public static string ConvertBytesToHexString(IntPtr a_in, UInt32 size, bool a_group)
        {
            string hex = ExtendedBitConverter.ToString(a_in, 0, (Int32)size);
            hex = hex.ToUpper();

            if (size == 1)
            {
                return hex;
            } // end if

            if (size == 2)
            {   
                return hex.Replace("-", "");
            } // end if

            if (a_group)
            {
                string workstring = ExtendedBitConverter.ToString(a_in, 0, (Int32)size);
                workstring = workstring.ToUpper();

                string[] arr = Converters.SplitString(workstring, '-');
                
                UInt32 I = 0;

                while (I < (arr.Length >> 2))
                {
                    if (I != 0)
                    {
                        hex = hex + '-';
                    } // end if

                    hex = hex + (arr[I * 4] + arr[I * 4 + 1] + arr[I * 4 + 2] + arr[I * 4 + 3]);

                    I += 1;
                } // end while

                return hex;
            } // end if

            return hex.Replace("-", "");
        } // end function ConvertBytesToHexString

        public static byte[] ConvertHexStringToBytes(string a_in)
        {
            a_in.Replace("-", "");

            byte[] result = new byte[a_in.Length >> 1];

            for (Int32 i = 0, j = 0; i < a_in.Length; i += 2, j += 1)
		    {
                string byteStr = a_in.Substring(i, 2);
                result[j] = (byte)Convert.ToChar(Convert.ToUInt32(byteStr, 16));
            } // end for

            return result;
        } // end function ConvertHexStringToBytes

        public static byte[] ConvertStringToBytes(string a_in)
        {
            byte[] arr = new byte[a_in.Length];
            for (Int32 i = 0; i < a_in.Length; i++)
		    {
                arr[i] = (byte)(a_in[i]);
            } // end for

            return arr;
        } // end function ConvertStringToBytes

        public static string[] SplitString(string S, char Delimiter)
        {
            Int32 PosStart, PosDel, SplitPoints, I, Len;
            string[] result = new string[] { };

            if (!(S == null || S.Length == 0))
            {
                SplitPoints = 0;
                for (Int32 i = 0; i < S.Length; i++)
			    {
                    if (Delimiter == S[i])
                        SplitPoints += 1;
                } // end for

                Array.Resize(ref result, SplitPoints + 1);

                I = 0;
                Len = 1;
                PosStart = 0;
                PosDel = (Int32)S.IndexOf(Delimiter, 0);
                while (PosDel != -1)
                {
                    result[I] = S.Substring(PosStart, PosDel - PosStart);
                    PosStart = PosDel + Len;
                    PosDel = (Int32)S.IndexOf(Delimiter, PosStart);
                    I += 1;
                } // end while

                result[I] = S.Substring(PosStart, S.Length);
            } // end if

            return result;
        } // end function SplitString

    }
}
