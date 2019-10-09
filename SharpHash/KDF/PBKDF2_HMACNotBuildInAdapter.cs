using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.KDF
{
    public class PBKDF2_HMACNotBuildInAdapter : Base.KDF, IPBKDF2_HMACNotBuildIn
    {
        private IHash hash = null;
        private IHMAC HMAC = null;
        private byte[] Password = null, Salt = null, buffer = null;
        private UInt32 IterationCount, Block;
        private Int32 BlockSize, startIndex, endIndex;

        protected static string InvalidArgument = "\"bc (ByteCount)\" Argument must be a value greater than zero.";
        protected static string InvalidIndex = "Invalid start or end index in the internal buffer.";
        protected static string UninitializedInstance = "\"IHash\" instance is uninitialized.";
        protected static string EmptyPassword = "Password can't be empty.";
        protected static string EmptySalt = "Salt can't be empty.";
        protected static string IterationtooSmall = "Iteration must be greater than zero.";

        public PBKDF2_HMACNotBuildInAdapter(IHash a_underlyingHash, byte[] a_password, 
            byte[] a_salt, UInt32 a_iterations)
	    {

            hash = a_underlyingHash.Clone();

            buffer = new byte[0];
		    Password = new byte[a_password.Length];
            // Copy Password
            Utils.Utils.memcopy(Password, a_password, a_password.Length);

		    Salt = new byte[a_salt.Length];
            // Copy Salt
            Utils.Utils.memcopy(Salt, a_salt, a_salt.Length);

            IterationCount = a_iterations;

		    Initialize();
        } // end constructor

        override public byte[] GetBytes(Int32 bc)
        {
            Int32 LOffset, LSize, LRemainder;

            if (bc <= 0)
                throw new ArgumentOutOfRangeHashLibException(InvalidArgument);

            byte[] LKey = new byte[bc];

            LOffset = 0;
            LSize = endIndex - startIndex;
            if (LSize > 0)
            {
                if (bc >= LSize)
                {
                    unsafe
                    {
                        fixed (byte* dPtr = &LKey[0], sPtr = &buffer[startIndex])
                        {
                            Utils.Utils.memmove((IntPtr)dPtr, (IntPtr)sPtr, LSize);
                        }
                    }
                    
                    startIndex = 0;
                    endIndex = 0;
                    LOffset = LOffset + LSize;
                } // end if
                else
                {
                    unsafe
                    {
                        fixed (byte* dPtr = &LKey[0], sPtr = &buffer[startIndex])
                        {
                            Utils.Utils.memmove((IntPtr)dPtr, (IntPtr)sPtr, bc);
                        }
                    }

                    startIndex = startIndex + bc;
                    return LKey;
                } // end else
            } // end if

            if ((startIndex != 0) && (endIndex != 0))
                throw new ArgumentHashLibException(InvalidIndex);

            while (LOffset < bc)
            {
                byte[] LT_block = Func();
                LRemainder = bc - LOffset;
                if (LRemainder > BlockSize)
                {
                    unsafe
                    {
                        fixed (byte* dPtr = &LKey[LOffset], sPtr = &LT_block[0])
                        {
                            Utils.Utils.memmove((IntPtr)dPtr, (IntPtr)sPtr, BlockSize);
                        }
                    }

                    LOffset = LOffset + BlockSize;
                } // end if
                else
                {
                    unsafe
                    {
                        fixed (byte* dPtr = &LKey[LOffset], sPtr = &LT_block[0],
                            dPtr2 = &buffer[startIndex], sPtr2 = &LT_block[0])
                        {
                            Utils.Utils.memmove((IntPtr)dPtr, (IntPtr)sPtr, LRemainder);
                            Utils.Utils.memmove((IntPtr)dPtr2, (IntPtr)sPtr2, BlockSize - LRemainder);
                        }
                    }

                    endIndex = endIndex + (BlockSize - LRemainder);
                    return LKey;
                } // end else
            } // end while

            return LKey;
        } // end function GetBytes

	    // initializes the state of the operation.
	    private void Initialize()
        {
            if (!(buffer == null || buffer.Length == 0))
                Utils.Utils.memset(buffer, (char)0, buffer.Length * sizeof(byte));

            HMAC = new HMACNotBuildInAdapter(hash);

            HMAC.SetKey(Password);
            BlockSize = (Int32)HMAC.GetHashSize();

            Array.Resize(ref buffer, BlockSize);

            Block = 1;
            startIndex = 0;
            endIndex = 0;
        } // end function Initialize

        // iterative hash function
        private byte[] Func()
        {
            byte[] INT_block = GetBigEndianBytes(Block);
            HMAC.Initialize();

            HMAC.TransformBytes(Salt, 0, Salt.Length);
            HMAC.TransformBytes(INT_block, 0, INT_block.Length);

            byte[] temp = HMAC.TransformFinal().GetBytes();
            byte[] ret = temp;

            UInt32 i = 2;
            Int32 j = 0;
            while (i <= IterationCount)
            {
                temp = HMAC.ComputeBytes(temp).GetBytes();
                j = 0;
                while (j < BlockSize)
                {
                    ret[j] = (byte)(ret[j] ^ temp[j]);
                    j++;
                } // end while
                i++;
            } // end while

            Block++;

            return ret;
        } // end function Func

        /// <summary>
        /// Encodes an integer into a 4-byte array, in big endian.
        /// </summary>
        /// <param name="i">The integer to encode.</param>
        /// <returns>array of bytes, in big endian.</returns>
        private static byte[] GetBigEndianBytes(UInt32 i)
	    {
            byte[] b = BitConverter.GetBytes(i);
            byte[] invertedBytes = new byte[] { b[3], b[2], b[1], b[0] };
		    if (BitConverter.IsLittleEndian)
			    return invertedBytes;
		    return b;
	    } // end function GetBigEndianBytes

    }
}
