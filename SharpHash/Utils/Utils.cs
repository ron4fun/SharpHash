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

        public unsafe static void memmove(ref byte[] dest, byte[] src, Int32 n)
        {
            fixed (byte* destPtr = &dest[0], srcPtr = &src[0])
            {
                memmove((IntPtr)destPtr, (IntPtr)srcPtr, n);
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

        public static void memset(ref byte[] array, byte value)
        {
            if (array == null)
            {
                throw new ArgumentNullException("array");
            }

            int block = 32, index = 0;
            int length = Math.Min(block, array.Length);

            //Fill the initial array
            while (index < length)
            {
                array[index++] = value;
            }

            length = array.Length;
            while (index < length)
            {
                Buffer.BlockCopy(array, 0, array, index, Math.Min(block, length - index));
                index += block;
                block *= 2;
            }
        } // end function MemSet

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
