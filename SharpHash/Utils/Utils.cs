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
using System.Runtime.CompilerServices;

namespace SharpHash.Utils
{
    public static class Utils
    {
        public unsafe static void Memcopy(ref byte[] dest, byte[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            Array.Copy(src, indexSrc, dest, indexDest, n);
        }

        public unsafe static void Memcopy(ref UInt32[] dest, UInt32[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            Array.Copy(src, indexSrc, dest, indexDest, n);
        }

        public unsafe static void Memcopy(ref UInt64[] dest, UInt64[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            Array.Copy(src, indexSrc, dest, indexDest, n);
        }

        public unsafe static void Memcopy(IntPtr dest, IntPtr src, Int32 n)
        {
            Memmove(dest, src, n);
        }

        // A function to copy block of 'n' bytes from source
        // address 'src' to destination address 'dest'.
        public unsafe static void Memmove(IntPtr dest, IntPtr src, Int32 n)
        {
            Unsafe.CopyBlock((IntPtr*)dest, (IntPtr*)src, (uint)n);
        }

        public unsafe static void Memmove(ref byte[] dest, byte[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            Array.Copy(src, indexSrc, dest, indexDest, n);
        } //

        public unsafe static void Memmove(ref UInt32[] dest, UInt32[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            Array.Copy(src, indexSrc, dest, indexDest, n);
        } //

        public unsafe static void Memmove(ref UInt64[] dest, UInt64[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            Array.Copy(src, indexSrc, dest, indexDest, n);
        } //

        public unsafe static void Memset(IntPtr dest, byte value, Int32 n)
        {
            // Typecast src and dest address to (byte *)
            byte* cdest = (byte*)dest;

            // Copy data to dest[]
            for (Int32 i = 0; i < n; i++)
                cdest[i] = value;
        } // end function memset

        public static unsafe void Memset(ref byte[] array, byte value, Int32 index = 0)
        {
            if (array.Empty()) return;

            Int32 block = 32, startIndex = index, size = array.Length;
            Int32 length = index + block < size ? index + block : size;

            // Fill the initial array
            while (index < length)
                array[index++] = value;

            length = array.Length;
            while (index < size)
            {
                Buffer.BlockCopy(array, startIndex, array, index, Math.Min(block, size - index));
                index += block;
                block *= 2;
            } // end while
        } // end function memSet

        public static unsafe void Memset(ref UInt32[] array, byte value, Int32 index = 0)
        {
            if (array.Empty()) return;

            fixed (UInt32* ptrStart = array)
            {
                Unsafe.InitBlock((IntPtr*)(ptrStart + index), value, (UInt32)array.Length * sizeof(UInt32));
            }
        } // end function memset

        public static unsafe void Memset(ref UInt64[] array, byte value, Int32 index = 0, Int32 n = -1)
        {
            if (array.Empty()) return;

            fixed (UInt64* ptrStart = array)
            {
                Unsafe.InitBlock((IntPtr*)(ptrStart + index), value, (UInt32)array.Length * sizeof(UInt64));
            }
        } // end function memset

        public static byte[] Concat(byte[] x, byte[] y)
        {
            byte[] result = new byte[0];
            Int32 index = 0;

            if (x.Empty())
            {
                if (y.Empty()) return result;

                Array.Resize(ref result, y.Length);
                Memcopy(ref result, y, y.Length);

                return result;
            } // end if

            if (y.Empty())
            {
                Array.Resize(ref result, x.Length);
                Memcopy(ref result, x, x.Length);

                return result;
            } // end if

            Array.Resize(ref result, x.Length + y.Length);

            // If Lengths are equal
            if (x.Length == y.Length)
            {
                // Multi fill array
                while (index < y.Length)
                {
                    result[index] = x[index];
                    result[x.Length + index] = y[index++];
                } // end while
            } // end if
            else if (x.Length > y.Length)
            {
                // Multi fill array
                while (index < y.Length)
                {
                    result[index] = x[index];
                    result[x.Length + index] = y[index++];
                } // end while

                while (index < x.Length)
                    result[index] = x[index++];
            } // end else if
            else if (y.Length > x.Length)
            {
                // Multi fill array
                while (index < x.Length)
                {
                    result[index] = x[index];
                    result[x.Length + index] = y[index++];
                } // end while

                while (index < y.Length)
                    result[x.Length + index] = y[index++];
            } // ende else if

            return result;
        } // end function Concat

        public static UInt32[] Concat(UInt32[] x, UInt32[] y)
        {
            UInt32[] result = new UInt32[0];
            Int32 index = 0;

            if (x.Empty())
            {
                if (y.Empty()) return result;

                Array.Resize(ref result, y.Length);
                Memcopy(ref result, y, y.Length);

                return result;
            } // end if

            if (y.Empty())
            {
                Array.Resize(ref result, x.Length);
                Memcopy(ref result, x, x.Length);

                return result;
            } // end if

            Array.Resize(ref result, x.Length + y.Length);

            // If Lengths are equal
            if (x.Length == y.Length)
            {
                // Multi fill array
                while (index < y.Length)
                {
                    result[index] = x[index];
                    result[x.Length + index] = y[index++];
                } // end while
            } // end if
            else if (x.Length > y.Length)
            {
                // Multi fill array
                while (index < y.Length)
                {
                    result[index] = x[index];
                    result[x.Length + index] = y[index++];
                } // end while

                while (index < x.Length)
                    result[index] = x[index++];
            } // end else if
            else if (y.Length > x.Length)
            {
                // Multi fill array
                while (index < x.Length)
                {
                    result[index] = x[index];
                    result[x.Length + index] = y[index++];
                } // end while

                while (index < y.Length)
                    result[x.Length + index] = y[index++];
            } // ende else if

            return result;
        } // end function Concat

    }
}