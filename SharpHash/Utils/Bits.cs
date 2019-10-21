using System;

namespace SharpHash.Utils
{
    internal static class Bits
    {
        public static unsafe void ReverseByteArray(IntPtr Source, IntPtr Dest, Int64 size)
        {
            byte* ptr_src = (byte*)Source;
            byte* ptr_dest = (byte*)Dest;

            ptr_dest = ptr_dest + (size - 1);
            while (size > 0)
            {
                *ptr_dest = *ptr_src;
                ptr_src += 1;
                ptr_dest -= 1;
                size -= 1;
            } // end while
        } // end function ReverseByteArray

        public static Int32 ReverseBytesInt32(Int32 value)
        {
            Int32 i1 = value & 0xFF;
            Int32 i2 = Bits.Asr32(value, 8) & 0xFF;
            Int32 i3 = Bits.Asr32(value, 16) & 0xFF;
            Int32 i4 = Bits.Asr32(value, 24) & 0xFF;

            return (i1 << 24) | (i2 << 16) | (i3 << 8) | (i4 << 0);
        } // end function ReverseBytesInt32

        public static byte ReverseBitsUInt8(byte value)
        {
            byte result = (byte)(((value >> 1) & 0x55) | ((value << 1) & 0xAA));
            result = (byte)(((result >> 2) & 0x33) | ((result << 2) & 0xCC));
            return (byte)(((result >> 4) & 0x0F) | ((result << 4) & 0xF0));
        } // end function ReverseBitsUInt8

        public static UInt16 ReverseBytesUInt16(UInt16 value)
        {
            return (UInt16)(((value & (UInt32)(0xFF)) << 8 | (value & (UInt32)(0xFF00)) >> 8));
        } // end function ReverseBytesUInt16

        public static UInt32 ReverseBytesUInt32(UInt32 value)
        {
            return (value & (UInt32)(0x000000FF)) << 24 |
                (value & (UInt32)(0x0000FF00)) << 8 |
                (value & (UInt32)(0x00FF0000)) >> 8 |
                (value & (UInt32)(0xFF000000)) >> 24;
        } // end function ReverseBytesUInt32

        public static UInt64 ReverseBytesUInt64(UInt64 value)
        {
            return (value & (UInt64)(0x00000000000000FF)) << 56 |
                (value & (UInt64)(0x000000000000FF00)) << 40 |
                (value & (UInt64)(0x0000000000FF0000)) << 24 |
                (value & (UInt64)(0x00000000FF000000)) << 8 |
                (value & (UInt64)(0x000000FF00000000)) >> 8 |
                (value & (UInt64)(0x0000FF0000000000)) >> 24 |
                (value & (UInt64)(0x00FF000000000000)) >> 40 |
                (value & (UInt64)(0xFF00000000000000)) >> 56;
        } // end function ReverseBytesUInt64

        public static Int32 Asr32(Int32 value, Int32 ShiftBits)
        {
            return (Int32)((UInt32)((UInt32)((UInt32)(value) >> (ShiftBits & 31)) |
                ((UInt32)((Int32)((UInt32)(0 - (UInt32)((UInt32)(value) >> 31)) &
                    (UInt32)((Int32)(0 - (Convert.ToInt32((ShiftBits & 31) != 0)))))) << (32 - (ShiftBits & 31)))));
        } // end function Asr32

        public static Int64 Asr64(Int64 value, Int64 ShiftBits)
        {
            return (Int64)((UInt64)((UInt64)((UInt64)(value) >> (Int32)(ShiftBits & 63)) |
                ((UInt64)((UInt64)((UInt64)(0 - (UInt64)((UInt64)(value) >> 63)) &
                    (UInt64)((Int64)(0 - (Convert.ToInt32((ShiftBits & 63) != 0)))))) << (Int32)(64 - (ShiftBits & 63)))));
        } // end function Asr64

        public static UInt32 RotateLeft32(UInt32 a_value, Int32 a_n)
        {
            a_n = a_n & 31;
            return (a_value << a_n) | (a_value >> (32 - a_n));
        } // end function RotateLeft32

        public static UInt64 RotateLeft64(UInt64 a_value, Int32 a_n)
        {
            a_n = a_n & 63;
            return (a_value << a_n) | (a_value >> (64 - a_n));
        } // end function RotateLeft64

        public static UInt32 RotateRight32(UInt32 a_value, Int32 a_n)
        {
            a_n = a_n & 31;
            return (a_value >> a_n) | (a_value << (32 - a_n));
        } // end function RotateRight32

        public static UInt64 RotateRight64(UInt64 a_value, Int32 a_n)
        {
            a_n = a_n & 63;
            return (a_value >> a_n) | (a_value << (64 - a_n));
        } // end function RotateRight64
    }
}