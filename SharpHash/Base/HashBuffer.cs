using System;

namespace SharpHash.Base
{
    internal sealed class HashBuffer
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
            Utils.Utils.memcopy(ref result.data, data, data.Length);

            return result;
        }

        public unsafe bool Feed(IntPtr a_data, Int32 a_length_a_data, Int32 a_length)
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

            fixed (byte* bDest = &data[0])
            {
                Utils.Utils.memmove((IntPtr)bDest, a_data, Length * sizeof(byte));
            }

            pos = pos + Length;

            return IsFull;
        } // end function Feed

        public unsafe bool Feed(IntPtr a_data, Int32 a_length_a_data,
            ref Int32 a_start_index, ref Int32 a_length, ref UInt64 a_processed_bytes)
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

            fixed (byte* bDest = &data[pos])
            {
                Utils.Utils.memmove((IntPtr)bDest, (IntPtr)((byte*)a_data + a_start_index), Length * sizeof(byte));
            }

            pos = pos + Length;
            a_start_index = a_start_index + Length;
            a_length = a_length - Length;
            a_processed_bytes = a_processed_bytes + (UInt64)(Length);

            return IsFull;
        } // end function Feed

        public byte[] GetBytes()
        {
            pos = 0;

            byte[] result = new byte[data.Length];
            Utils.Utils.memcopy(ref result, data, data.Length);

            return result;
        } // end function GetBytes

        public unsafe byte[] GetBytesZeroPadded()
        {
            Utils.Utils.memset(ref data, 0, pos, data.Length - pos);

            pos = 0;

            byte[] result = new byte[data.Length];
            Utils.Utils.memcopy(ref result, data, data.Length);

            return result;
        } // end function GetBytesZeroPadded

<<<<<<< Updated upstream
        public bool IsEmpty => pos == 0;
	
	    public bool IsFull => pos == data.Length;

        public Int32 Length => data.Length; // end property Length
=======
        public bool IsEmpty
        {
            get
            {
                return pos == 0;
            }
        } // end property IsEmpty

        public bool IsFull
        {
            get
            {
                return pos == data.Length;
            }
        } // end property IsFull

        public Int32 Length
        {
            get
            {
                return data.Length;
            }
        } // end property Length

        public Int32 Position
        {
            get
            {
                return pos;
            }
        } // end property Position
>>>>>>> Stashed changes

        public Int32 Position =>  pos;
        
        public void Initialize()
        {
            pos = 0;

            Utils.Utils.memset(ref data, 0);
        } // end function Initialize

        public override string ToString()
        {
            return $"HashBuffer, Length: {Length}, Pos: {Position}, IsEmpty: {IsEmpty}";
        } // end function ToString
    }
}