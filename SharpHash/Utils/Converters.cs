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

using System;
using System.Globalization;
using System.Text;

namespace SharpHash.Utils
{
    public static class Converters
    {
        public static unsafe void swap_copy_str_to_u32(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
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

        public static unsafe void be32_copy(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
        {
            if (BitConverter.IsLittleEndian)
            {
                swap_copy_str_to_u32(src, src_index, dest, dest_index, length);
            } // end if
            else
            {
                Utils.Memmove((IntPtr)((byte*)dest + dest_index), (IntPtr)((byte*)src + src_index), length);
            } // end else
        } // end function be32_copy

        public static unsafe void be64_copy(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
        {
            if (BitConverter.IsLittleEndian)
            {
                swap_copy_str_to_u64(src, src_index, dest, dest_index, length);
            } // end if
            else
            {
                Utils.Memmove((IntPtr)((byte*)dest + dest_index), (IntPtr)((byte*)src + src_index), length);
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

        public static unsafe void le32_copy(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
        {
            if (BitConverter.IsLittleEndian)
            {
                Utils.Memmove((IntPtr)((byte*)dest + dest_index), (IntPtr)((byte*)src + src_index), length);
            } // end if
            else
            {
                swap_copy_str_to_u32(src, src_index, dest, dest_index, length);
            } // end else
        } // end function le32_copy

        public static unsafe void le64_copy(IntPtr src, Int32 src_index,
            IntPtr dest, Int32 dest_index, Int32 length)
        {
            if (BitConverter.IsLittleEndian)
            {
                Utils.Memmove((IntPtr)((byte*)dest + dest_index), (IntPtr)((byte*)src + src_index), length);
            } // end if
            else
            {
                swap_copy_str_to_u64(src, src_index, dest, dest_index, length);
            } // end else
        } // end function le64_copy

        public static unsafe UInt32 ReadBytesAsUInt32LE(IntPtr a_in, Int32 a_index)
        {
            UInt32 result = *(UInt32*)((byte*)a_in + a_index);
            return Converters.le2me_32((Int32)result);
        } // end function ReadBytesAsUInt32LE

        public static unsafe UInt64 ReadBytesAsUInt64LE(IntPtr a_in, Int32 a_index)
        {
            UInt64 result = *(UInt64*)((byte*)a_in + a_index);
            return Converters.le2me_64(result);
        } // end function ReadBytesAsUInt64LE

        public static byte[] ReadUInt32AsBytesLE(UInt32 a_in)
        {
            byte[] arr = new byte[4];
            arr[0] = (byte)a_in;
            arr[1] = (byte)(a_in >> 8);
            arr[2] = (byte)(a_in >> 16);
            arr[3] = (byte)(a_in >> 24);

            return arr;
        } // end function ReadUInt32AsBytesLE

        public static void ReadUInt32AsBytesLE(UInt32 a_Input, ref byte[] a_Output, Int32 a_Index)
        {
            a_Output[a_Index] = (byte)(a_Input);
            a_Output[a_Index + 1] = (byte)(a_Input >> 8); 
            a_Output[a_Index + 2] = (byte)(a_Input >> 16);
            a_Output[a_Index + 3] = (byte)(a_Input >> 24);
        } // end function ReadUInt32AsBytesLE

        public static void ReadUInt32AsBytesBE(UInt32 a_Input, ref byte[] a_Output, Int32 a_Index)
        {
            a_Output[a_Index] = (byte)(a_Input >> 24);
            a_Output[a_Index + 1] = (byte)(a_Input >> 16);
            a_Output[a_Index + 2] = (byte)(a_Input >> 8);
            a_Output[a_Index + 3] = (byte)(a_Input);
        } // end function ReadUInt32AsBytesBE

        public static byte[] ReadUInt64AsBytesLE(UInt64 a_in)
        {
            byte[] arr = new byte[8];
            arr[0] = (byte)a_in;
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

        public static unsafe string ConvertBytesToHexString(byte[] a_in, bool a_group, char delimeter = '-')
        {
            if (a_in == null || a_in.Length == 0) return "";

            fixed (byte* bPtr = a_in)
            {
                return ConvertBytesToHexString((IntPtr)bPtr, (UInt32)a_in.Length, a_group, delimeter);
            }
        } // end function ConvertBytesToHexString

        public static string ConvertBytesToHexString(IntPtr a_in, UInt32 size, bool a_group, char delimeter = '-')
        {
            string hex = ExtendedBitConverter.ToString(a_in, 0, (Int32)size, delimeter);
            hex = hex.ToUpper();

            if (size == 1)
            {
                return hex;
            } // end if

            if (size == 2)
            {
                return hex.Replace(delimeter.ToString(), "", true, CultureInfo.CurrentCulture);
            } // end if

            if (a_group) return hex;

            return hex.Replace(delimeter.ToString(), "", 
                true, CultureInfo.CurrentCulture);
        } // end function ConvertBytesToHexString

        public static byte[] ConvertHexStringToBytes(string a_in, char delimeter = '-')
        {
            a_in.Replace(delimeter.ToString(), "");

            byte[] result = new byte[a_in.Length >> 1];

            for (Int32 i = 0, j = 0; i < a_in.Length; i += 2, j += 1)
            {
                string byteStr = a_in.Substring(i, 2);
                result[j] = (byte)Convert.ToChar(Convert.ToUInt32(byteStr, 16));
            } // end for

            return result;
        } // end function ConvertHexStringToBytes

        public static byte[] ConvertStringToBytes(string a_in, Encoding encoding)
        {
            if (String.IsNullOrEmpty(a_in)) return new byte[0];
            return encoding.GetBytes(a_in);
        } // end function ConvertStringToBytes
    }
}