using System;

namespace SharpHash.Base
{
    public class HashBuffer
    {

        private byte[] data = null;
        private Int32 pos = 0;


        public HashBuffer(Int32 a_length)
	    {
            data = new byte[a_length];
		    Initialize();
        } // end constructor

        public HashBuffer Clone()
	    {
		    HashBuffer result = new HashBuffer(0);
 
		    result.pos = pos;

            result.data = new byte[data.Length];
            unsafe
            {
                fixed (byte* bDest = &result.data[0], bSrc = &data[0])
                {
                    Utils.Utils.memmove((IntPtr)bDest, (IntPtr)bSrc, data.Length * sizeof(byte));
                }
            }

            return result;
	    }

        public bool Feed(IntPtr a_data, Int32 a_length_a_data, Int32 a_length)
        {
            Int32 Length;

            if (a_length_a_data == 0)
            {
                return false;
            } // end if

            if (a_length == 0)
            {
                return false;
            } // end if

            Length = data.Length - pos;
            if (Length > a_length)
            {
                Length = a_length;
            } // end if

            unsafe
            {
                fixed (byte* bDest = &data[0])
                {
                    Utils.Utils.memmove((IntPtr)bDest, a_data, Length * sizeof(byte));
                }
            }
            
            pos = pos + Length;

            return GetIsFull();
        } // end function Feed

        public bool Feed(IntPtr a_data, Int32 a_length_a_data,
            Int32 a_start_index, Int32 a_length, UInt64 a_processed_bytes)
        {
            Int32 Length;

            if (a_length_a_data == 0)
            {
                return false;
            } // end if

            if (a_length == 0)
            {
                return false;
            } // end if

            Length = data.Length - pos;
            if (Length > a_length)
            {
                Length = a_length;
            } // end if

            unsafe
            {
                fixed (byte* bDest = &data[pos])
                {
                    Utils.Utils.memmove((IntPtr)bDest, (IntPtr)((byte*)a_data)[a_start_index], Length * sizeof(byte));
                }
            }
            
            pos = pos + Length;
            a_start_index = a_start_index + Length;
            a_length = a_length - Length;
            a_processed_bytes = a_processed_bytes + (UInt64)(Length);

            return GetIsFull();
        } // end function Feed

        public byte[] GetBytes()
        {
            pos = 0;
            return data;
        } // end function GetBytes

        public byte[] GetBytesZeroPadded()
        {
            unsafe
            {
                fixed (byte* bDest = &data[pos])
                {
                    Utils.Utils.memset((IntPtr)bDest, (char)0, (data.Length - pos) * sizeof(byte));
                }
            }
            
            pos = 0;
            return data;
        } // end function GetBytesZeroPadded

        public bool GetIsEmpty()
	    {
		    return pos == 0;
	    } // end function GetIsEmpty
	
	    public bool GetIsFull()
	    {
		    return pos == data.Length;
	    } // end function GetIsFull
	
	    public Int32 GetLength()
	    {
		    return data.Length;
	    } // end function GetLength
	
	    public Int32 GetPos()
	    {
		    return pos;
	    } // end function GetPos
	
	    public void Initialize()
        {
            pos = 0;
            
            unsafe
            {
                fixed (byte* bDest = &data[0])
                {
                    Utils.Utils.memset((IntPtr)bDest, (char)0, data.Length * sizeof(byte));
                }
            }
        } // end function Initialize

        public override string ToString()
	    {
		    return $"HashBuffer, Length: {GetLength()}, Pos: {GetPos()}, IsEmpty: {GetIsEmpty()}";
	    } // end function ToString
	


    }
}
