using System;

namespace SharpHash.Utils
{
    public static class Utils
    {
        public static void memcopy(byte[] dest, byte[] src, Int32 n, 
            Int32 indexSrc = 0, Int32 indexDest = 0)
        {
            unsafe
            {
                fixed (byte* destPtr = &dest[indexDest], srcPtr = &src[indexSrc])
                {
                    memcopy((IntPtr)destPtr, (IntPtr)srcPtr, n);
                }
            }
        }

        public static void memcopy(IntPtr dest, IntPtr src, Int32 n)
        {
            unsafe
            {
                // Typecast src and dest address to (char *)
                char* csrc = (char*)src;
                char* cdest = (char*)dest;

                // Copy data from csr[] to dest[]
                for (int i = 0; i < n; i++)
                    cdest[i] = csrc[i];
            }
        }

        // A function to copy block of 'n' bytes from source
        // address 'src' to destination address 'dest'.
        public static void memmove(IntPtr dest, IntPtr src, Int32 n)
        {
            unsafe
            {
                // Typecast src and dest address to (char *)
                char* csrc = (char*)src;
                char* cdest = (char*)dest;

                // Create a temporary array to hold data of src
                char[] temp = new char[n];

                // Copy data from csr[] to temp[]
                for (int i = 0; i < n; i++)
                    temp[i] = csrc[i];

                // Copy data from temp[] to cdest[]
                for (int i = 0; i < n; i++)
                    cdest[i] = temp[i];
            }
        }

        public static void memmove(byte[] dest, byte[] src, Int32 n)
        {
            unsafe
            {
                fixed (byte* destPtr = &dest[0], srcPtr = &src[0])
                {
                    memmove((IntPtr)destPtr, (IntPtr)srcPtr, n);
                }
            }
        }

        public static void memset(IntPtr dest, char value, Int32 n)
        {
            unsafe
            {
                // Typecast src and dest address to (char *)
                char* cdest = (char*)dest;

                // Copy data to dest[]
                for (int i = 0; i < n; i++)
                    cdest[i] = value;
            }
        }

        public static void memset(byte[] dest, char value, Int32 n)
        {
            unsafe
            {
                fixed (byte* destPtr = &dest[0])
                {
                    memset((IntPtr)destPtr, value, n);
                }
            }
        }

    }
}
