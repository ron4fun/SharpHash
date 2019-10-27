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

namespace SharpHash.Utils
{
    public static class Utils
    {
        public unsafe static void memcopy(ref byte[] dest, byte[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            fixed (byte* destPtr = &dest[indexDest], srcPtr = &src[indexSrc])
            {
                memcopy((IntPtr)destPtr, (IntPtr)srcPtr, n);
            }
        }

        public unsafe static void memcopy(ref UInt32[] dest, UInt32[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            fixed (UInt32* destPtr = &dest[indexDest], srcPtr = &src[indexSrc])
            {
                memcopy((IntPtr)destPtr, (IntPtr)srcPtr, n * sizeof(UInt32));
            }
        }

        public unsafe static void memcopy(ref UInt64[] dest, UInt64[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            fixed (UInt64* destPtr = &dest[indexDest], srcPtr = &src[indexSrc])
            {
                memcopy((IntPtr)destPtr, (IntPtr)srcPtr, n * sizeof(UInt64));
            }
        }

        public unsafe static void memcopy(IntPtr dest, IntPtr src, Int32 n)
        {
            // Typecast src and dest address to (byte *)
            byte* csrc = (byte*)src;
            byte* cdest = (byte*)dest;

            // Copy data from csr[] to dest[]
            for (int i = 0; i < n; i++)
                cdest[i] = csrc[i];
        }

        // A function to copy block of 'n' bytes from source
        // address 'src' to destination address 'dest'.
        public unsafe static void memmove(IntPtr dest, IntPtr src, Int32 n)
        {
            // Typecast src and dest address to (byte *)
            byte* csrc = (byte*)src;
            byte* cdest = (byte*)dest;

            // Create a temporary array to hold data of src
            byte[] temp = new byte[n];

            // Copy data from csr[] to temp[]
            for (int i = 0; i < n; i++)
                temp[i] = csrc[i];

            // Copy data from temp[] to cdest[]
            for (int i = 0; i < n; i++)
                cdest[i] = temp[i];
        }

        public unsafe static void memmove(ref byte[] dest, byte[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            fixed (byte* destPtr = &dest[indexDest], srcPtr = &src[indexSrc])
            {
                memmove((IntPtr)destPtr, (IntPtr)srcPtr, n);
            }
        }

        public unsafe static void memmove(ref UInt32[] dest, UInt32[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            fixed (UInt32* destPtr = &dest[indexDest], srcPtr = &src[indexSrc])
            {
                memmove((IntPtr)destPtr, (IntPtr)srcPtr, n * sizeof(UInt32));
            }
        }

        public unsafe static void memmove(ref UInt64[] dest, UInt64[] src, Int32 n,
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            fixed (UInt64* destPtr = &dest[indexDest], srcPtr = &src[indexSrc])
            {
                memmove((IntPtr)destPtr, (IntPtr)srcPtr, n * sizeof(UInt64));
            }
        }

        public unsafe static void memset(IntPtr dest, byte value, Int32 n)
        {
            // Typecast src and dest address to (byte *)
            byte* cdest = (byte*)dest;

            // Copy data to dest[]
            for (Int32 i = 0; i < n; i++)
                cdest[i] = value;
        } // end function MemSet

        public static unsafe void memset(ref byte[] array, byte value, Int32 index = 0, Int32 n = -1)
        {
            if (array == null || array.Length == 0) return;

            fixed (byte* destPtr = &array[index])
            {
                memset((IntPtr)destPtr, value, (n == -1 ? array.Length : n) * sizeof(byte));
            }
        } // end function MemSet

        public static unsafe void memset(ref UInt32[] array, byte value, Int32 index = 0, Int32 n = -1)
        {
            if (array == null || array.Length == 0) return;

            fixed (UInt32* destPtr = &array[index])
            {
                memset((IntPtr)destPtr, value, (n == -1 ? array.Length : n) * sizeof(UInt32));
            }
        } // end function memset

        public static unsafe void memset(ref UInt64[] array, byte value, Int32 index = 0, Int32 n = -1)
        {
            if (array == null || array.Length == 0) return;

            fixed (UInt64* destPtr = &array[index])
            {
                memset((IntPtr)destPtr, value, (n == -1 ? array.Length : n) * sizeof(UInt64));
            }
        } // end function memset

        public static byte[] Concat(byte[] x, byte[] y)
        {
            byte[] result = new byte[0];
            Int32 index = 0;

            if (x == null || x.Length == 0)
            {
                if (y == null) return result;

                Array.Resize(ref result, y.Length);
                memcopy(ref result, y, y.Length);

                return result;
            } // end if

            if (y == null || y.Length == 0)
            {
                Array.Resize(ref result, x.Length);
                memcopy(ref result, x, x.Length);

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