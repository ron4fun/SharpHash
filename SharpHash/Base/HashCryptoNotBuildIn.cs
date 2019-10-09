using SharpHash.Interfaces;
using System;

namespace SharpHash.Base
{
    public abstract class BlockHash : Hash, IBlockHash
    {
        protected HashBuffer buffer = null;
        UInt64 processed_bytes = 0;

        public BlockHash(Int32 a_hash_size, Int32 a_block_size, Int32 a_buffer_size = -1)
		: base(a_hash_size, a_block_size)
        {
            if (a_buffer_size == -1)
                a_buffer_size = a_block_size;

            buffer = new HashBuffer(a_buffer_size);
        } // end constructor

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
	    {
            unsafe
            {
                fixed (byte* ptr_a_data = &a_data[0])
                {
                    if (!buffer.GetIsEmpty())
                    {
                        if (buffer.Feed((IntPtr)ptr_a_data, (Int32)a_data.Length, a_index, a_length, processed_bytes))
                            TransformBuffer();
                    } // end if

                    while (a_length >= buffer.GetLength())
                    {
                        processed_bytes = processed_bytes + (UInt64)(buffer.GetLength());
                        TransformBlock((IntPtr)ptr_a_data, buffer.GetLength(), a_index);
                        a_index = a_index + buffer.GetLength();
                        a_length = a_length - buffer.GetLength();
                    } // end while

                    if (a_length > 0)
                        buffer.Feed((IntPtr)ptr_a_data, (Int32)a_data.Length, a_index, a_length, processed_bytes);
                }
            }
	    } // end function TransformBytes

	    override public void Initialize()
        {
            buffer.Initialize();
            processed_bytes = 0;
        } // end function Initialize
        
        override public IHashResult TransformFinal()
        {
            Finish();

            byte[] tempresult = GetResult();

            Initialize();

            return new HashResult(tempresult);
        } // end function TransformFinal

        private void TransformBuffer()
        {
            unsafe
            {
                fixed (byte* bPtr = &buffer.GetBytes()[0])
                {
                    TransformBlock((IntPtr)bPtr, buffer.GetLength(), 0);
                }
            }
        } // end function TransformBuffer

        protected abstract void Finish();

	    protected abstract void TransformBlock(IntPtr a_data,
		        Int32 a_data_length, Int32 a_index);

	    protected abstract byte[] GetResult();

    }
}
