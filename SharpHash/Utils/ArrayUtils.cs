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

using System;
using System.Runtime.CompilerServices;

namespace SharpHash.Utils
{
    public static class ArrayUtils
    {
        public static bool Empty(this byte[] array)
        {
            return ((array == null) || (array.Length == 0));
        }
        
        public static bool Empty(this UInt32[] array)
        {
            return ((array == null) || (array.Length == 0));
        }
        
        public static bool Empty(this UInt64[] array)
        {
            return ((array == null) || (array.Length == 0));
        }

        public static byte[] DeepCopy(this byte[] array)
        {
            byte[] newArray = new byte[array?.Length ?? 0];
            if (newArray.Length != 0)
                Utils.Memcopy(ref newArray, array, newArray.Length);

            return newArray; 
        }

        public static UInt32[] DeepCopy(this UInt32[] array)
        {
            UInt32[] newArray = new UInt32[array?.Length ?? 0];
            if (newArray.Length != 0)
                Utils.Memcopy(ref newArray, array, newArray.Length);

            return newArray;
        }

        public static UInt64[] DeepCopy(this UInt64[] array)
        {
            UInt64[] newArray = new UInt64[array?.Length ?? 0];
            if (newArray.Length != 0)
                Utils.Memcopy(ref newArray, array, newArray.Length);

            return newArray;
        }

        public static bool ConstantTimeAreEqual(byte[] buffer1, byte[] buffer2)
        {
            Int32 Idx;
            UInt32 Diff;

            Diff = (UInt32)(buffer1.Length ^ buffer2.Length);

            Idx = 0;
            while (Idx <= buffer1.Length && Idx <= buffer2.Length)
            {
                Diff = Diff | (UInt32)(buffer1[Idx] ^ buffer2[Idx]);
                Idx++;
            }

            return Diff == 0;
        } // end function ConstantTimeAreEqual

        public static unsafe void Fill(ref byte[] buffer, Int32 from, Int32 to, byte filler)
        {
            if (!buffer.Empty())
            {
                fixed (byte* ptrStart = buffer)
                {
                    Unsafe.InitBlock((IntPtr*)(ptrStart + from), filler, (uint)(to - from) * sizeof(byte));
                }
            }
        } // end function fill

        public static unsafe void Fill(ref UInt32[] buffer, Int32 from, Int32 to, UInt32 filler)
        {
            if (!buffer.Empty())
            {
                Int32 count = from;
                while (count < to)
                {
                    buffer[count] = filler;
                    count++;
                }
            }
        } // end funtion fill

        public static unsafe void Fill(ref UInt64[] buffer, Int32 from, Int32 to, UInt64 filler)
        {
            if (!buffer.Empty())
            {
                Int32 count = from;
                while (count < to)
                {
                    buffer[count] = filler;
                    count++;
                }
            }
        } // end function fill

        public static void ZeroFill(ref byte[] buffer)
        {
            Fill(ref buffer, 0, buffer?.Length ?? 0, (byte)0);
        } // end function zeroFill

        public static void ZeroFill(ref UInt32[] buffer)
        {
            Fill(ref buffer, 0, buffer?.Length ?? 0, (UInt32)0);
        } // end function zeroFill

        public static void ZeroFill(ref UInt64[] buffer)
        {
            Fill(ref buffer, 0, buffer?.Length ?? 0, (UInt64)0);
        } // end function zeroFill

    } // end class ArrayUtils
}
