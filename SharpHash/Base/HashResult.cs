using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Base
{
    public class HashResult : IHashResult
    {
        private byte[] hash = null;

        private static string ImpossibleRepresentationInt32 = "Current Data Structure cannot be Represented as an 'Int32' Type.";
        private static string ImpossibleRepresentationUInt8 = "Current Data Structure cannot be Represented as an 'UInt8' Type.";
        private static string ImpossibleRepresentationUInt16 = "Current Data Structure cannot be Represented as an 'UInt16' Type.";
        private static string ImpossibleRepresentationUInt32 = "Current Data Structure cannot be Represented as an 'UInt32' Type.";
        private static string ImpossibleRepresentationUInt64 = "Current Data Structure cannot be Represented as an 'UInt64' Type.";

        public HashResult()
        {
            hash = new byte[] { };
        } // end constructor

        public HashResult(UInt64 a_hash)
        {
            hash = new byte[8];

		    hash[0] = (byte)(a_hash >> 56);
            hash[1] = (byte)(a_hash >> 48);
            hash[2] = (byte)(a_hash >> 40);
            hash[3] = (byte)(a_hash >> 32);
            hash[4] = (byte)(a_hash >> 24);
            hash[5] = (byte)(a_hash >> 16);
            hash[6] = (byte)(a_hash >> 8);
            hash[7] = (byte)(a_hash);
        } // end constructor

        public HashResult(byte[] a_hash)
        {
            if (a_hash == null || a_hash.Length == 0)
                hash = new byte[] { };

            else
            {
                hash = new byte[a_hash.Length];
                Utils.Utils.memcopy(hash, a_hash, a_hash.Length);
            } // end else
        } // end constructor

        public HashResult(UInt32 a_hash)
        {
            hash = new byte[4];

		    hash[0] = (byte)(a_hash >> 24);
            hash[1] = (byte)(a_hash >> 16);
            hash[2] = (byte)(a_hash >> 8);
            hash[3] = (byte)(a_hash);
        } // end constructor

        public HashResult(byte a_hash)
        {
            hash = new byte[1];
		    hash[0] = a_hash;
	    } // end constructor
	
	    public HashResult(UInt16 a_hash)
        {
            hash = new byte[2];

            hash[0] = (byte)(a_hash >> 8);
            hash[1] = (byte)(a_hash);
	    } // end constructor
	
	    public HashResult(Int32 a_hash)
        {
            hash = new byte[4];

		    hash[0] = (byte)(Utils.Bits.Asr32(a_hash, 24));
		    hash[1] = (byte)(Utils.Bits.Asr32(a_hash, 16));
		    hash[2] = (byte)(Utils.Bits.Asr32(a_hash, 8));
		    hash[3] = (byte)(a_hash);
	    } // end constructor

        // Copy Constructor
        public HashResult(HashResult right)
        {
            if (right.hash == null || right.hash.Length == 0)
            {
                hash = new byte[] { };
            }
            else
            {
                hash = new byte[right.hash.Length];
                unsafe
                {
                    fixed (byte* bDest = &hash[0], bSrc = &right.hash[0])
                    {
                        Utils.Utils.memmove((IntPtr)bDest, (IntPtr)bSrc, right.hash.Length * sizeof(byte));
                    }
                }
            }
        }

        virtual public bool CompareTo(IHashResult a_hashResult)
	    {
		    return HashResult.SlowEquals(a_hashResult.GetBytes(), hash);
	    } // end function CompareTo

	    virtual public byte[] GetBytes()
	    {
		    return hash;
	    } // end function GetBytes

	    override public Int32 GetHashCode()
	    {
            byte[] TempHolder = new byte[hash.Length];
            
            unsafe
            {
                fixed (byte* tPtr = &TempHolder[0], srcPtr = &hash[0])
                {
                    Utils.Utils.memcopy((IntPtr)tPtr, (IntPtr)srcPtr, hash.Length * sizeof(byte));

                    Converters.toUpper((IntPtr)tPtr, hash.Length);

                    Int32 LResult = 0, I = 0, Top = hash.Length;

                    while (I < Top)
                    {
                        LResult = (Int32)Utils.Bits.RotateLeft32((UInt32)LResult, 5);
                        LResult = (Int32)((UInt32)LResult ^ (UInt32)(tPtr[(Int32)I]));
                        I += 1;
                    } // end while

                    return LResult;
                }
            }
	    } // end function GetHashCode

	    virtual public Int32 GetInt32()
	    {
		    if (hash.Length != 4)
		    {
			    throw new InvalidOperationHashLibException(ImpossibleRepresentationInt32);
		    } // end if
		
		    return ((Int32)(hash[0]) << 24) | ((Int32)(hash[1]) << 16) | 
			    ((Int32)(hash[2]) << 8) | (Int32)(hash[3]);
	    } // end function GetInt32
		
	    virtual public byte GetUInt8()
	    {
		    if (hash.Length != 1)
		    {
			    throw new InvalidOperationHashLibException(ImpossibleRepresentationUInt8);
		    } // end if
		
		    return hash[0];
	    } // end function GetUInt8
			
	    virtual public UInt16 GetUInt16()
	    {
		    if (hash.Length != 2)
		    {
			    throw new InvalidOperationHashLibException(ImpossibleRepresentationUInt16);
		    } // end if
		 
		    return (UInt16)((hash[0] << 8) | hash[1]);
	    } // end function GetUInt16
				
	    virtual public UInt32 GetUInt32()
	    {
		    if (hash.Length != 4)
		    {
			    throw new InvalidOperationHashLibException(ImpossibleRepresentationUInt32);
		    } // end if
		
		    return ((UInt32)(hash[0]) << 24) | ((UInt32)(hash[1]) << 16) |
			    ((UInt32)(hash[2]) << 8) | (UInt32)(hash[3]);
	    } // end function GetUInt32
					
	    virtual public UInt64 GetUInt64()
	    {
		    if (hash.Length != 8)
		    {
			    throw new InvalidOperationHashLibException(ImpossibleRepresentationUInt64);
		    } // end if
		
		    return ((UInt64)(hash[0]) << 56) | ((UInt64)(hash[1]) << 48) | ((UInt64)(hash[2]) << 40) | ((UInt64)(hash[3]) << 32) |
			    ((UInt64)(hash[4]) << 24) | ((UInt64)(hash[5]) << 16) | ((UInt64)(hash[6]) << 8) | (UInt64)(hash[7]);
	    } // end function GetUInt64
						
	    static protected bool SlowEquals(byte[] a_ar1, byte[] a_ar2)
        {
            UInt32 diff = (UInt32)(a_ar1.Length ^ a_ar2.Length), I = 0;

            while (I <= (a_ar1.Length - 1) && I <= (a_ar2.Length - 1))
            {
                diff = diff | (UInt32)(a_ar1[I] ^ a_ar2[I]);
                I += 1;
            } // end while

            return diff == 0;
        } // end function SlowEquals

        virtual public string ToString(bool a_group = false)
	    {
		    return Converters.ConvertBytesToHexString(hash, a_group);
	    } // end function ToString
        
    }
}
