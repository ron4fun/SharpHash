using System;

namespace SharpHash.Utils
{
    public static class Utils
    {
        public unsafe static void memcopy(byte[] dest, byte[] src, Int32 n, 
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

        public unsafe static void memmove(byte[] dest, byte[] src, Int32 n)
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

        public static void memset(byte[] array, byte value)
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

    }
}
